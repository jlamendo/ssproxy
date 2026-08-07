"""Regression: ssproxy's scrub_text_fixed_length must preserve BYTE
length of the wire body (not just character length). Multi-byte UTF-8
in a captured value span used to shrink the encoded body, causing
downstream JSON parsers (Anthropic /v1/messages) to reject the
shifted body with "unexpected character: line 1 column N".

Live-reproduced 2026-08-07 by principal-engineer-9 (400-at-col-180858).
Fix: byte_length_redaction, called at every scrub_text_fixed_length
callsite.
"""
from __future__ import annotations

import random

from ssproxy import scrub_secrets as S


def _bytes(s: str) -> int:
    return len(s.encode("utf-8"))


def test_labeled_value_with_emoji_preserves_byte_length() -> None:
    sample = 'a "api_key":"abc🎉def" b'
    scrubbed = S.scrub_text_fixed_length(sample)
    assert _bytes(scrubbed) == _bytes(sample), (sample, scrubbed)


def test_labeled_value_with_accented_chars_preserves_byte_length() -> None:
    sample = 'x "password":"tokéen-ünïcode" y'
    scrubbed = S.scrub_text_fixed_length(sample)
    assert _bytes(scrubbed) == _bytes(sample)


def test_labeled_value_all_ascii_still_preserves_byte_length() -> None:
    sample = 'x "token":"aaaaaaaaaaaa" y'
    scrubbed = S.scrub_text_fixed_length(sample)
    assert _bytes(scrubbed) == _bytes(sample)
    assert len(scrubbed) == len(sample)  # ASCII: chars == bytes


def test_fuzz_100_mixed_utf8_labeled_values() -> None:
    random.seed(42)
    unicode_pool = "🎉🚀🐛📦😀café résumé naïve"
    ascii_pool = "abcdefghij0123456789"
    labels = ["api_key", "password", "secret", "token", "access_key"]
    for _ in range(100):
        label = random.choice(labels)
        val_len = random.randint(5, 30)
        parts = []
        for _ in range(val_len):
            if random.random() < 0.15:
                parts.append(random.choice(unicode_pool))
            else:
                parts.append(random.choice(ascii_pool))
        val = "".join(parts)
        sample = f'"{label}":"{val}"'
        scrubbed = S.scrub_text_fixed_length(sample)
        assert _bytes(scrubbed) == _bytes(sample), (
            f"byte-length mismatch: {sample!r} → {scrubbed!r} "
            f"({_bytes(sample)} → {_bytes(scrubbed)} bytes)"
        )


def test_uri_userinfo_with_utf8_preserves_byte_length() -> None:
    # URI userinfo with a multi-byte password
    sample = "https://user:p@ss🎉word@example.com/path"
    scrubbed = S.scrub_text_fixed_length(sample)
    assert _bytes(scrubbed) == _bytes(sample), (sample, scrubbed)
