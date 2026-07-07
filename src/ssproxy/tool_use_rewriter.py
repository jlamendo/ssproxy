"""Anthropic tool_use block rewriter — SSE streaming + JSON non-streaming.

Purpose
-------
Rewrite ``tool_use`` blocks in Anthropic ``/v1/messages`` responses on
the fly. Two response shapes are handled:

  * **Non-streaming** (``application/json``): a single JSON body with a
    ``content: [...]`` array. Use :func:`rewrite_message_json` — walk
    the array and apply a caller-supplied rewrite hook to each
    ``tool_use`` block.

  * **Streaming SSE** (``text/event-stream``): a series of
    ``content_block_start`` / ``content_block_delta`` /
    ``content_block_stop`` frames. Buffering the whole stream to
    rewrite would defeat streaming, so :class:`SSEToolUseRewriter`
    provides a per-flow callable that mitmproxy can install as
    ``flow.response.stream``. It passes frames through unchanged
    EXCEPT for tool_use blocks whose ``name`` a subclass claims via
    :meth:`~SSEToolUseRewriter.should_capture`; captured blocks are
    buffered until ``content_block_stop`` and then re-emitted with
    the subclass's :meth:`~SSEToolUseRewriter.rewrite` applied.

When to subclass
----------------
Override :meth:`~SSEToolUseRewriter.should_capture` to declare which
tool names you rewrite (called once per ``content_block_start``, so
cheap). Override :meth:`~SSEToolUseRewriter.rewrite` to transform
``(name, input)`` into the replacement pair. The block's ``id`` is
always preserved: the client's next-turn tool_result echoes back on
the same id, so mutating it would break the tool round-trip.

Example
-------
::

    class NameRemap(SSEToolUseRewriter):
        def should_capture(self, name):
            return name == "OldName"
        def rewrite(self, name, input):
            return ("NewName", input)

    class AskRewriter(SSEToolUseRewriter):
        def should_capture(self, name):
            return name == "AskUserQuestion"
        def rewrite(self, name, input):
            return ("cork.ask", translate_ask_input(input))

Failure mode
------------
Any exception inside the frame handler falls through to pass-through
of the ORIGINAL frame bytes with capture state reset — the proxy
must never break a response because of a rewriter bug. Errors are
logged via the stdlib :mod:`logging` module for operator visibility.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


ANTHROPIC_HOST = "api.anthropic.com"
ANTHROPIC_MESSAGES_PATH_PREFIX = "/v1/messages"


# ─── JSON (non-streaming) rewrite ──────────────────────────────────


ToolUseRewriteFn = Callable[[str, dict], Optional[tuple[str, dict]]]


def rewrite_message_json(body: dict, rewrite_fn: ToolUseRewriteFn) -> int:
    """Rewrite ``tool_use`` blocks in a decoded Anthropic ``/v1/messages``
    non-streaming response body.

    ``rewrite_fn(name, input)`` returns ``(new_name, new_input)`` to
    rewrite the block, or ``None`` to leave it untouched. The block's
    ``id`` is always preserved.

    Mutates ``body`` in place. Returns the number of blocks rewritten
    (0 if none matched or the body's shape is unexpected).
    """
    if not isinstance(body, dict):
        return 0
    content = body.get("content")
    if not isinstance(content, list):
        return 0
    rewrites = 0
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") != "tool_use":
            continue
        name = block.get("name")
        if not isinstance(name, str):
            continue
        try:
            result = rewrite_fn(name, block.get("input") or {})
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ssproxy SSEToolUseRewriter: JSON rewrite hook crashed "
                "on tool=%s (%r); leaving block untouched", name, exc,
            )
            continue
        if result is None:
            continue
        new_name, new_input = result
        block["name"] = new_name
        block["input"] = new_input
        rewrites += 1
    return rewrites


# ─── SSE (streaming) rewrite ───────────────────────────────────────


def _find_sep(buf: bytearray) -> Optional[tuple[int, int]]:
    """Return ``(frame_end_index, sep_len)`` for the earliest SSE
    frame terminator in ``buf`` (``\\n\\n`` or ``\\r\\n\\r\\n``), or
    None if no complete frame is present.
    """
    i_lf = buf.find(b"\n\n")
    i_crlf = buf.find(b"\r\n\r\n")
    if i_lf == -1 and i_crlf == -1:
        return None
    if i_lf == -1:
        return (i_crlf, 4)
    if i_crlf == -1:
        return (i_lf, 2)
    if i_crlf < i_lf:
        return (i_crlf, 4)
    return (i_lf, 2)


def _parse_sse_frame(frame: bytes) -> Optional[dict]:
    """Return ``{'_event_name': str|None, '_data': any}`` parsed from an
    SSE frame, or None for comment-only / empty frames.
    """
    frame = frame.strip(b"\r\n")
    if not frame:
        return None
    if frame.startswith(b":"):
        return None  # SSE comment (keep-alive)
    event_name: Optional[str] = None
    data_parts: list[bytes] = []
    for line in frame.split(b"\n"):
        line = line.rstrip(b"\r")
        if not line or line.startswith(b":"):
            continue
        if line.startswith(b"event:"):
            event_name = line[6:].lstrip(b" ").decode("utf-8", errors="replace")
        elif line.startswith(b"data:"):
            data_parts.append(line[5:].lstrip(b" "))
    if not data_parts and event_name is None:
        return None
    data_raw = b"\n".join(data_parts) if data_parts else b""
    data_obj: Any = None
    if data_raw:
        try:
            data_obj = json.loads(data_raw)
        except Exception:  # noqa: BLE001
            data_obj = data_raw.decode("utf-8", errors="replace")
    return {"_event_name": event_name, "_data": data_obj}


class SSEToolUseRewriter:
    """Per-flow SSE parser + ``tool_use`` block rewriter.

    Instance is callable — assign to ``flow.response.stream`` and
    mitmproxy invokes it per body chunk with ``b""`` at EOF.

    Subclass hooks:

      * :meth:`should_capture` — return True to intercept a tool_use
        block by that name; False to pass through untouched.
      * :meth:`rewrite` — given ``(name, input)`` after full assembly,
        return ``(new_name, new_input)``. Default is identity.

    The captured block's ``id`` and ``index`` are preserved verbatim:
    the client's next-turn tool_result is keyed on ``id``, and later
    frames in the same stream key on ``index``, so a mismatch would
    break the round-trip.

    Emits ONE ``content_block_start`` + ONE ``content_block_delta``
    carrying the fully-assembled translated input as
    ``input_json_delta.partial_json`` + ONE ``content_block_stop`` per
    captured block. claude-code's SSE parser concatenates all
    ``partial_json`` values and ``json.loads`` at ``content_block_stop``,
    so one large chunk is functionally identical to N small ones.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._capturing = False
        self._cap_index: Any = None
        self._cap_id: Any = None
        self._cap_name: Optional[str] = None
        self._cap_partials: list[str] = []

    # ── subclass hooks ─────────────────────────────────────────

    def should_capture(self, name: str) -> bool:
        """Return True to buffer + rewrite a tool_use block whose
        ``name`` field equals ``name``. Default: pass-through.
        """
        return False

    def rewrite(self, name: str, input: dict) -> tuple[str, dict]:
        """Transform ``(name, input)`` at ``content_block_stop`` time.
        Default: identity (useful only if a subclass overrides
        :meth:`should_capture` to force a re-emit without name/input
        changes, e.g. to log the raw call).
        """
        return (name, input)

    # ── mitmproxy stream callback ──────────────────────────────

    def __call__(self, chunk: bytes) -> bytes:
        if not chunk:
            # EOF. If mid-capture, emit a best-effort synthetic closer
            # so the client sees a well-formed tool_use.
            tail = bytearray()
            if self._capturing:
                tail.extend(self._flush_pending_capture(interrupted=True))
                self._reset_capture()
            tail.extend(self._buf)
            self._buf.clear()
            return bytes(tail)
        try:
            self._buf.extend(chunk)
        except Exception:  # noqa: BLE001
            return chunk

        out = bytearray()
        while True:
            found = _find_sep(self._buf)
            if found is None:
                break
            end, sep_len = found
            frame = bytes(self._buf[:end])
            sep = bytes(self._buf[end:end + sep_len])
            del self._buf[:end + sep_len]
            try:
                emitted = self._handle_frame(frame, sep)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ssproxy SSEToolUseRewriter: frame handler crashed "
                    "(%r); passing frame through untouched", exc,
                )
                if self._capturing:
                    self._reset_capture()
                emitted = frame + sep
            if emitted:
                out.extend(emitted)
        return bytes(out)

    # ── frame handling ─────────────────────────────────────────

    def _handle_frame(self, frame: bytes, sep: bytes) -> bytes:
        parsed = _parse_sse_frame(frame)
        if parsed is None:
            return frame + sep
        data_obj = parsed.get("_data")

        if not self._capturing:
            # Enter capture on a content_block_start whose block is a
            # tool_use claimed by should_capture().
            if (
                isinstance(data_obj, dict)
                and data_obj.get("type") == "content_block_start"
            ):
                cb = data_obj.get("content_block")
                if (
                    isinstance(cb, dict)
                    and cb.get("type") == "tool_use"
                ):
                    name = cb.get("name")
                    if isinstance(name, str) and self.should_capture(name):
                        self._capturing = True
                        self._cap_index = data_obj.get("index")
                        self._cap_id = cb.get("id")
                        self._cap_name = name
                        self._cap_partials = []
                        return b""  # suppress the original start
            return frame + sep

        # ── mid-capture ──
        if isinstance(data_obj, dict):
            dt = data_obj.get("type")
            if dt == "content_block_delta" and data_obj.get("index") == self._cap_index:
                delta = data_obj.get("delta")
                if isinstance(delta, dict) and delta.get("type") == "input_json_delta":
                    partial = delta.get("partial_json")
                    if isinstance(partial, str):
                        self._cap_partials.append(partial)
                # Any delta on our captured block is suppressed.
                return b""
            if dt == "content_block_stop" and data_obj.get("index") == self._cap_index:
                out = self._flush_pending_capture(interrupted=False)
                self._reset_capture()
                return out

        # A frame that isn't part of our tool_use block — pass through.
        return frame + sep

    # ── capture flush ──────────────────────────────────────────

    def _flush_pending_capture(self, interrupted: bool) -> bytes:
        full = "".join(self._cap_partials)
        try:
            tool_input = json.loads(full) if full.strip() else {}
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ssproxy SSEToolUseRewriter: partial_json reassembly "
                "failed (%r) for id=%s; forwarding empty input",
                exc, self._cap_id,
            )
            tool_input = {}

        try:
            new_name, new_input = self.rewrite(self._cap_name or "", tool_input)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "ssproxy SSEToolUseRewriter: rewrite hook crashed "
                "(%r); re-emitting original name+input", exc,
            )
            new_name, new_input = (self._cap_name or "", tool_input)

        idx = self._cap_index
        tid = self._cap_id

        start_data = {
            "type": "content_block_start",
            "index": idx,
            "content_block": {
                "type": "tool_use",
                "id": tid,
                "name": new_name,
                "input": {},
            },
        }
        delta_data = {
            "type": "content_block_delta",
            "index": idx,
            "delta": {
                "type": "input_json_delta",
                "partial_json": json.dumps(new_input, ensure_ascii=False),
            },
        }
        stop_data = {
            "type": "content_block_stop",
            "index": idx,
        }
        if interrupted:
            logger.info(
                "ssproxy SSEToolUseRewriter: emitting rewritten tool_use "
                "on interrupted SSE stream (id=%s idx=%r)", tid, idx,
            )

        pieces: list[bytes] = []
        for evname, obj in (
            ("content_block_start", start_data),
            ("content_block_delta", delta_data),
            ("content_block_stop", stop_data),
        ):
            pieces.append(
                b"event: " + evname.encode("utf-8")
                + b"\ndata: " + json.dumps(obj, ensure_ascii=False).encode("utf-8")
                + b"\n\n"
            )
        return b"".join(pieces)

    def _reset_capture(self) -> None:
        self._capturing = False
        self._cap_index = None
        self._cap_id = None
        self._cap_name = None
        self._cap_partials = []
