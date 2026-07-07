"""Behavioral tests for ssproxy.tool_use_rewriter.

Covers:
  * JSON (non-streaming) rewrite_message_json — no-op, mismatch, rewrite,
    input translation, id-preservation.
  * SSE (streaming) SSEToolUseRewriter — pass-through, capture-emit,
    partial-json reassembly, EOF-interruption, exception isolation.

Run: python3 tests/test_tool_use_rewriter.py
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from ssproxy.tool_use_rewriter import (  # noqa: E402
    SSEToolUseRewriter,
    rewrite_message_json,
    _parse_sse_frame,
    _find_sep,
)


FAILURES: list[str] = []


def assert_eq(label: str, got, want) -> None:
    if got != want:
        FAILURES.append(f"[{label}] want={want!r} got={got!r}")


def assert_true(label: str, cond: bool, note: str = "") -> None:
    if not cond:
        FAILURES.append(f"[{label}] expected True{': ' + note if note else ''}")


# ─── JSON (non-streaming) ──────────────────────────────────────────


def test_json_no_content_field() -> None:
    body = {"id": "msg_1"}
    n = rewrite_message_json(body, lambda name, inp: ("X", inp))
    assert_eq("json/no-content", n, 0)


def test_json_no_tool_use_blocks() -> None:
    body = {"content": [{"type": "text", "text": "hi"}]}
    n = rewrite_message_json(body, lambda name, inp: ("X", inp))
    assert_eq("json/no-tool-use", n, 0)


def test_json_rewrite_matches() -> None:
    body = {
        "content": [
            {"type": "text", "text": "here"},
            {
                "type": "tool_use",
                "id": "toolu_abc",
                "name": "OldName",
                "input": {"a": 1},
            },
            {
                "type": "tool_use",
                "id": "toolu_def",
                "name": "Skip",
                "input": {"b": 2},
            },
        ]
    }

    def hook(name, inp):
        if name == "OldName":
            return ("NewName", {"translated": inp["a"] * 2})
        return None

    n = rewrite_message_json(body, hook)
    assert_eq("json/rewrite/count", n, 1)
    assert_eq("json/rewrite/name", body["content"][1]["name"], "NewName")
    assert_eq("json/rewrite/input", body["content"][1]["input"], {"translated": 2})
    assert_eq("json/rewrite/id-preserved", body["content"][1]["id"], "toolu_abc")
    # Skip block untouched
    assert_eq("json/skip/name", body["content"][2]["name"], "Skip")
    assert_eq("json/skip/input", body["content"][2]["input"], {"b": 2})


def test_json_hook_raises() -> None:
    body = {"content": [{"type": "tool_use", "id": "t", "name": "X", "input": {}}]}

    def boom(name, inp):
        raise RuntimeError("bug")

    n = rewrite_message_json(body, boom)
    assert_eq("json/hook-raises/count", n, 0)
    assert_eq("json/hook-raises/untouched", body["content"][0]["name"], "X")


# ─── SSE frame parsing ─────────────────────────────────────────────


def test_find_sep_none() -> None:
    assert_eq("sep/none", _find_sep(bytearray(b"partial")), None)


def test_find_sep_lf() -> None:
    assert_eq("sep/lf", _find_sep(bytearray(b"abc\n\ndef")), (3, 2))


def test_find_sep_crlf() -> None:
    assert_eq("sep/crlf", _find_sep(bytearray(b"abc\r\n\r\ndef")), (3, 4))


def test_find_sep_prefer_earliest() -> None:
    # \n\n at index 3, \r\n\r\n at index 8 — earliest wins
    assert_eq("sep/earliest", _find_sep(bytearray(b"abc\n\ndef\r\n\r\n")), (3, 2))


def test_parse_sse_frame_data_only() -> None:
    p = _parse_sse_frame(b'data: {"a":1}')
    assert_eq("parse/data-only/data", p["_data"], {"a": 1})
    assert_eq("parse/data-only/event", p["_event_name"], None)


def test_parse_sse_frame_with_event() -> None:
    p = _parse_sse_frame(b'event: content_block_start\ndata: {"type":"content_block_start"}')
    assert_eq("parse/event/name", p["_event_name"], "content_block_start")
    assert_eq("parse/event/data-type", p["_data"]["type"], "content_block_start")


def test_parse_sse_frame_comment() -> None:
    assert_eq("parse/comment", _parse_sse_frame(b": keepalive"), None)


# ─── SSE streaming rewriter ────────────────────────────────────────


class _Uppercaser(SSEToolUseRewriter):
    """Rewrite input.q -> uppercase for tool_use blocks named 'Ask'."""

    def should_capture(self, name: str) -> bool:
        return name == "Ask"

    def rewrite(self, name: str, input: dict) -> tuple[str, dict]:
        return ("cork.echo", {"q_upper": input.get("q", "").upper()})


def _frame(event_name: str, data: dict) -> bytes:
    return (
        b"event: " + event_name.encode() + b"\ndata: "
        + json.dumps(data).encode() + b"\n\n"
    )


def test_sse_passthrough_no_match() -> None:
    """A tool_use with a name the subclass doesn't claim passes through
    unmodified byte-for-byte.
    """
    rw = _Uppercaser()
    input_bytes = b""
    # Whole stream: text block, tool_use we don't claim, message_stop
    input_bytes += _frame("content_block_start", {
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "text", "text": ""},
    })
    input_bytes += _frame("content_block_delta", {
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": "hello"},
    })
    input_bytes += _frame("content_block_stop", {
        "type": "content_block_stop", "index": 0,
    })
    input_bytes += _frame("content_block_start", {
        "type": "content_block_start", "index": 1,
        "content_block": {"type": "tool_use", "id": "t_1", "name": "OtherTool", "input": {}},
    })
    input_bytes += _frame("content_block_delta", {
        "type": "content_block_delta", "index": 1,
        "delta": {"type": "input_json_delta", "partial_json": "{\"x\":1}"},
    })
    input_bytes += _frame("content_block_stop", {
        "type": "content_block_stop", "index": 1,
    })
    output = rw(input_bytes) + rw(b"")
    assert_eq("sse/passthrough", output, input_bytes)


def test_sse_capture_and_rewrite() -> None:
    """A tool_use with a claimed name is captured, then re-emitted with
    the rewritten name + input as one start/one delta/one stop trio.
    """
    rw = _Uppercaser()
    stream = b""
    # Preceding text block untouched
    stream += _frame("content_block_start", {
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "text", "text": ""},
    })
    # Target tool_use
    stream += _frame("content_block_start", {
        "type": "content_block_start", "index": 1,
        "content_block": {"type": "tool_use", "id": "toolu_capture", "name": "Ask", "input": {}},
    })
    # Two partial_json deltas assembled
    stream += _frame("content_block_delta", {
        "type": "content_block_delta", "index": 1,
        "delta": {"type": "input_json_delta", "partial_json": "{\"q\":\"hel"},
    })
    stream += _frame("content_block_delta", {
        "type": "content_block_delta", "index": 1,
        "delta": {"type": "input_json_delta", "partial_json": "lo\"}"},
    })
    stream += _frame("content_block_stop", {
        "type": "content_block_stop", "index": 1,
    })
    # Trailing text block untouched
    stream += _frame("content_block_stop", {
        "type": "content_block_stop", "index": 0,
    })
    output = rw(stream) + rw(b"")

    # Parse the output frames back
    frames = [f for f in output.split(b"\n\n") if f]
    parsed = [_parse_sse_frame(f) for f in frames]
    # Find our rewritten start
    rewritten_start = None
    rewritten_delta = None
    rewritten_stop = None
    for p in parsed:
        if p is None:
            continue
        d = p.get("_data")
        if not isinstance(d, dict):
            continue
        if d.get("type") == "content_block_start" and d.get("index") == 1:
            rewritten_start = d
        elif d.get("type") == "content_block_delta" and d.get("index") == 1:
            rewritten_delta = d
        elif d.get("type") == "content_block_stop" and d.get("index") == 1:
            rewritten_stop = d
    assert_true("sse/rewrite/start-present", rewritten_start is not None)
    assert_true("sse/rewrite/delta-present", rewritten_delta is not None)
    assert_true("sse/rewrite/stop-present", rewritten_stop is not None)
    if rewritten_start is not None:
        cb = rewritten_start["content_block"]
        assert_eq("sse/rewrite/name", cb["name"], "cork.echo")
        assert_eq("sse/rewrite/id-preserved", cb["id"], "toolu_capture")
    if rewritten_delta is not None:
        payload = json.loads(rewritten_delta["delta"]["partial_json"])
        assert_eq("sse/rewrite/input", payload, {"q_upper": "HELLO"})


def test_sse_eof_interrupt_before_stop() -> None:
    """Mid-capture EOF still emits a well-formed rewritten tool_use."""
    rw = _Uppercaser()
    partial = _frame("content_block_start", {
        "type": "content_block_start", "index": 2,
        "content_block": {"type": "tool_use", "id": "t_2", "name": "Ask", "input": {}},
    }) + _frame("content_block_delta", {
        "type": "content_block_delta", "index": 2,
        "delta": {"type": "input_json_delta", "partial_json": "{\"q\":\"abc\"}"},
    })
    out = rw(partial) + rw(b"")
    # Should contain a start/delta/stop trio for the captured block
    assert_true("sse/eof/has-cork-echo", b"cork.echo" in out, "rewritten name missing")
    assert_true("sse/eof/has-stop",
                b"content_block_stop" in out and b"\"index\": 2" in out,
                "stop frame missing")


def test_sse_chunked_input() -> None:
    """Feeding the same stream in one-byte chunks produces the same
    output as feeding it whole.
    """
    stream = _frame("content_block_start", {
        "type": "content_block_start", "index": 3,
        "content_block": {"type": "text", "text": ""},
    }) + _frame("content_block_stop", {
        "type": "content_block_stop", "index": 3,
    })

    rw_whole = _Uppercaser()
    whole = rw_whole(stream) + rw_whole(b"")

    rw_chunky = _Uppercaser()
    chunky_out = bytearray()
    for byte in stream:
        chunky_out.extend(rw_chunky(bytes([byte])))
    chunky_out.extend(rw_chunky(b""))
    assert_eq("sse/chunked", bytes(chunky_out), whole)


def test_sse_hook_exception_isolated() -> None:
    """A crash inside .rewrite() falls through to re-emitting original
    name+input rather than corrupting the stream.
    """

    class Crasher(SSEToolUseRewriter):
        def should_capture(self, name: str) -> bool:
            return name == "Ask"

        def rewrite(self, name, input):
            raise RuntimeError("oops")

    rw = Crasher()
    stream = _frame("content_block_start", {
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "tool_use", "id": "t", "name": "Ask", "input": {}},
    }) + _frame("content_block_delta", {
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "input_json_delta", "partial_json": "{\"x\":1}"},
    }) + _frame("content_block_stop", {
        "type": "content_block_stop", "index": 0,
    })
    out = rw(stream) + rw(b"")
    # Crashed hook falls through — original name re-emitted
    assert_true("sse/hook-crash/original-name", b"\"name\": \"Ask\"" in out)
    # partial_json is a JSON string containing an escaped JSON object;
    # look for the escaped form.
    assert_true(
        "sse/hook-crash/original-input",
        b'\\"x\\": 1' in out or b'\\"x\\":1' in out,
    )


from ssproxy.tool_use_rewriter import force_identity_encoding


class _FakeHeaders(dict):
    """Case-insensitive minimal dict — mirrors mitmproxy.http.Headers'
    dict-style read/write API for these tests."""

    def __setitem__(self, k, v):
        super().__setitem__(k.lower(), v)

    def __getitem__(self, k):
        return super().__getitem__(k.lower())

    def get(self, k, default=None):
        return super().get(k.lower(), default)


class _FakeRequest:
    def __init__(self, headers=None):
        self.headers = _FakeHeaders(headers or {})


def test_force_identity_encoding_sets_header() -> None:
    req = _FakeRequest()
    assert force_identity_encoding(req) is True
    assert req.headers.get("accept-encoding") == "identity"


def test_force_identity_encoding_overwrites_existing() -> None:
    req = _FakeRequest({"accept-encoding": "gzip, deflate"})
    assert force_identity_encoding(req) is True
    assert req.headers.get("accept-encoding") == "identity"


def test_force_identity_encoding_returns_false_on_failure() -> None:
    class _BadRequest:
        @property
        def headers(self):
            raise RuntimeError("headers unavailable")

    # Must never raise — a helper bug can't be allowed to break the flow.
    assert force_identity_encoding(_BadRequest()) is False


# ─── main runner ──────────────────────────────────────────────────


def main() -> int:
    tests = [f for f in globals().values() if callable(f) and getattr(f, "__name__", "").startswith("test_")]
    for t in tests:
        t()
    if FAILURES:
        print(f"FAIL ({len(FAILURES)} failure(s)):")
        for f in FAILURES:
            print("  " + f)
        return 1
    print(f"OK — {len(tests)} test(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
