"""Preserve Anthropic-signed content blocks under same-length scrubbing.

Anthropic's extended-thinking API signs each emitted ``thinking``
content block. The signature is bound to the EXACT bytes of the
enclosing JSON object — ``{"type":"thinking","thinking":"<chain>",
"signature":"<sig>"}`` — and is re-validated when the client echoes
the block back on the next turn. Any byte modification inside that
span — even a same-length redaction — fails the check with
``messages.X.content.0: Invalid signature in thinking block`` (HTTP
400) and the request dies. ``redacted_thinking`` blocks carry an
opaque ``data`` field that's similarly server-bound.

The signed content is provably model-emitted (Anthropic-signed), so
it cannot carry an operator credential the way an echoed tool_result
or user_message can — the model didn't ingest one to regurgitate. We
lose no scrub coverage by skipping over signed spans; it's not where
creds live.

Public surface
--------------
:func:`find_signed_thinking_spans`
    Locate signed spans in a JSON request body.
:func:`scrub_text_fixed_length_preserve_signed`
    Same-length scrub that splices signed spans back verbatim.

Safety-net design
-----------------
Span discovery uses two independent guards:

  1. **Schema validation.** ``json.loads`` the body and confirm each
     block appears at the canonical position
     ``messages[*].content[*]`` of an ``assistant``-role message with
     the expected fields. This rejects smuggled fragments planted
     elsewhere (e.g. nested inside a tool_result content list) since
     those don't satisfy the schema.
  2. **Source-position validation.** For each schema-valid block,
     find its ``signature`` / ``data`` value bytes in the source text
     and verify they're IMMEDIATELY preceded by the literal key
     (``"signature":`` / ``"data":``) — guarding against a false
     positive where the fingerprint substring appears elsewhere in
     the body as ordinary string content.

Only when BOTH guards pass do we mark the enclosing object's byte
range as protected.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Optional


# Pre-compiled prefix matchers used by source-position validation.
# Match terminates at the position WHERE the signature/data value's
# opening `"` will start, so we compare against the previous bytes.
_SIG_PREFIX_RE = re.compile(r'"signature"\s*:\s*$')
_DATA_PREFIX_RE = re.compile(r'"data"\s*:\s*$')


def find_signed_thinking_spans(text: str) -> list[tuple[int, int]]:
    """Return sorted, non-overlapping ``[start, end)`` character ranges
    of JSON objects representing Anthropic-signed content blocks
    (``thinking`` or ``redacted_thinking``) at the canonical position
    ``messages[*].content[*]`` of an ``assistant``-role message.

    Returns ``[]`` on parse failure, on unrecognized body shape, or
    when no signed blocks are present — the caller then falls back to
    whole-body scrubbing.

    Indices are Python string (== UTF-8 code-point) indices over the
    decoded body. Callers that re-encode UTF-8 should verify byte
    length preservation as defense-in-depth.
    """
    if not isinstance(text, str) or not text:
        return []
    try:
        body = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(body, dict):
        return []
    messages = body.get("messages")
    if not isinstance(messages, list):
        return []

    # Collect (kind, fingerprint) pairs at the canonical position.
    fingerprints: list[tuple[str, str]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "thinking":
                sig = block.get("signature")
                if isinstance(sig, str) and sig:
                    fingerprints.append(("signature", sig))
            elif btype == "redacted_thinking":
                data = block.get("data")
                if isinstance(data, str) and data:
                    fingerprints.append(("data", data))
    if not fingerprints:
        return []

    # Locate each fingerprint in the source, verifying the preceding
    # bytes match the expected key. encode with ensure_ascii=False so
    # a signature containing non-ASCII matches the same encoding the
    # producer used.
    target_positions: set[int] = set()
    for kind, fp in fingerprints:
        encoded = json.dumps(fp, ensure_ascii=False)  # includes surrounding quotes
        prefix_re = _SIG_PREFIX_RE if kind == "signature" else _DATA_PREFIX_RE
        start = 0
        while True:
            idx = text.find(encoded, start)
            if idx == -1:
                break
            head = text[max(0, idx - 32):idx]
            if prefix_re.search(head):
                target_positions.add(idx)
                break  # first authentic match per fingerprint is enough
            start = idx + 1
    if not target_positions:
        return []

    # Forward pass: track object stack + string state. When a target
    # position is hit outside any string, mark the current stack
    # frame; emit the (open, close+1) span when that frame pops.
    spans: list[tuple[int, int]] = []
    stack: list[list] = []  # frames: [open_idx, has_target]
    in_str = False
    esc = False
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if not in_str and i in target_positions and stack:
            stack[-1][1] = True
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == '{':
                stack.append([i, False])
            elif c == '}':
                if not stack:
                    break  # unbalanced — bail with what we have
                open_idx, has_target = stack.pop()
                if has_target:
                    spans.append((open_idx, i + 1))
        i += 1

    if not spans:
        return []
    spans.sort()
    merged: list[tuple[int, int]] = []
    for s, e in spans:
        if merged and s < merged[-1][1]:
            # Shouldn't happen for valid JSON, but coalesce defensively.
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def scrub_text_fixed_length_preserve_signed(
    text: str,
    scrubber: Optional[Callable[[str], str]] = None,
) -> str:
    """Same-length scrub that keeps Anthropic-signed ``thinking`` /
    ``redacted_thinking`` block bytes untouched. Total length preserved
    end-to-end.

    Parameters
    ----------
    text : str
        Decoded UTF-8 body of an Anthropic ``/v1/messages`` request.
    scrubber : callable, optional
        A same-length scrub function. Defaults to
        :func:`ssproxy.scrub_text_fixed_length`. Pass a custom scrubber
        if the caller has its own configured pattern set.

    Returns
    -------
    str
        The scrubbed body. If ``text`` has no signed blocks, behaves
        identically to running ``scrubber(text)`` on the whole body.
    """
    if scrubber is None:
        from .scrub_secrets import scrub_text_fixed_length as _default
        scrubber = _default
    spans = find_signed_thinking_spans(text)
    if not spans:
        return scrubber(text)
    pieces: list[str] = []
    last = 0
    for start, end in spans:
        pieces.append(scrubber(text[last:start]))
        pieces.append(text[start:end])
        last = end
    pieces.append(scrubber(text[last:]))
    return "".join(pieces)
