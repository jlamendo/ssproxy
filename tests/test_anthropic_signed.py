"""Behavioral tests for ssproxy.anthropic_signed.

Covers:
  * find_signed_thinking_spans: empty / non-JSON / non-dict / wrong role
    / smuggled fragment rejection / thinking / redacted_thinking / mixed.
  * scrub_text_fixed_length_preserve_signed: length preservation with and
    without signed spans; signed bytes verbatim; non-signed bytes still
    get scrubbed by the delegated scrubber.

Run: python3 tests/test_anthropic_signed.py
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from ssproxy.anthropic_signed import (  # noqa: E402
    find_signed_thinking_spans,
    scrub_text_fixed_length_preserve_signed,
)
from ssproxy.scrub_secrets import scrub_text_fixed_length  # noqa: E402


FAILURES: list[str] = []


def assert_eq(label: str, got, want) -> None:
    if got != want:
        FAILURES.append(f"[{label}] want={want!r} got={got!r}")


def assert_true(label: str, cond: bool, note: str = "") -> None:
    if not cond:
        FAILURES.append(f"[{label}] expected True{': ' + note if note else ''}")


# ─── find_signed_thinking_spans ─────────────────────────────────────


def test_find_empty() -> None:
    assert_eq("find/empty", find_signed_thinking_spans(""), [])


def test_find_non_json() -> None:
    assert_eq("find/non-json", find_signed_thinking_spans("not json {"), [])


def test_find_non_dict() -> None:
    assert_eq("find/non-dict", find_signed_thinking_spans("[]"), [])


def test_find_no_messages() -> None:
    body = json.dumps({"foo": "bar"})
    assert_eq("find/no-messages", find_signed_thinking_spans(body), [])


def test_find_thinking_block() -> None:
    body_obj = {
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": "let me think",
                        "signature": "sig-abcdef",
                    }
                ],
            }
        ]
    }
    body = json.dumps(body_obj)
    spans = find_signed_thinking_spans(body)
    assert_eq("find/thinking/one-span", len(spans), 1)
    start, end = spans[0]
    # The extracted span should be a valid JSON object that round-trips
    extracted = body[start:end]
    parsed = json.loads(extracted)
    assert_eq("find/thinking/type", parsed["type"], "thinking")
    assert_eq("find/thinking/sig-preserved", parsed["signature"], "sig-abcdef")


def test_find_redacted_thinking_block() -> None:
    body_obj = {
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"type": "redacted_thinking", "data": "opaque-blob"}
                ],
            }
        ]
    }
    body = json.dumps(body_obj)
    spans = find_signed_thinking_spans(body)
    assert_eq("find/redacted/one-span", len(spans), 1)
    parsed = json.loads(body[spans[0][0]:spans[0][1]])
    assert_eq("find/redacted/data-preserved", parsed["data"], "opaque-blob")


def test_find_user_role_ignored() -> None:
    """A thinking block at a non-assistant role must not be treated as
    signed — it wasn't emitted by Anthropic so has no signature.
    """
    body_obj = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "thinking", "thinking": "smuggled", "signature": "sig-x"}
                ],
            }
        ]
    }
    body = json.dumps(body_obj)
    assert_eq("find/wrong-role", find_signed_thinking_spans(body), [])


def test_find_smuggled_inside_tool_result_ignored() -> None:
    """A JSON fragment shaped like a thinking block but placed inside a
    tool_result content list is NOT at the canonical position, so it
    doesn't count as signed.
    """
    body_obj = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "t",
                        "content": [
                            {"type": "thinking", "thinking": "s", "signature": "sig-s"}
                        ],
                    }
                ],
            }
        ]
    }
    body = json.dumps(body_obj)
    assert_eq("find/smuggled", find_signed_thinking_spans(body), [])


# ─── scrub_text_fixed_length_preserve_signed ────────────────────────


def test_preserve_no_signed_delegates() -> None:
    """No signed blocks — behavior is identical to the default scrubber."""
    text = "hi there"
    got = scrub_text_fixed_length_preserve_signed(text)
    assert_eq("preserve/no-signed", got, scrub_text_fixed_length(text))


def test_preserve_length_invariant() -> None:
    """Length preserved end-to-end, both with and without signed spans."""
    body_obj = {
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "hi"}]},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "hmm", "signature": "sig-len"}
                ],
            },
        ]
    }
    body = json.dumps(body_obj)
    out = scrub_text_fixed_length_preserve_signed(body)
    assert_eq("preserve/length-eq", len(out), len(body))


def test_preserve_signed_bytes_verbatim() -> None:
    """Bytes inside a signed span are copied verbatim (no scrub applied)."""
    body_obj = {
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": "reason",
                        "signature": "sig-verbatim",
                    }
                ],
            }
        ]
    }
    body = json.dumps(body_obj)
    spans = find_signed_thinking_spans(body)
    out = scrub_text_fixed_length_preserve_signed(body)
    for s, e in spans:
        assert_eq("preserve/verbatim", out[s:e], body[s:e])


def test_preserve_custom_scrubber() -> None:
    """A caller-supplied scrubber is used instead of the default."""
    marker = [0]

    def custom(s: str) -> str:
        marker[0] += 1
        return s  # length-preserving no-op

    body_obj = {"messages": [{"role": "user", "content": [{"type": "text", "text": "no signed here"}]}]}
    body = json.dumps(body_obj)
    out = scrub_text_fixed_length_preserve_signed(body, scrubber=custom)
    assert_eq("preserve/custom/output", out, body)
    assert_true("preserve/custom/called", marker[0] >= 1, "custom scrubber never called")


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
