"""Adversarial regression tests for the DO-Postgres credential-leak class.

Context: on 2026-08-03 a raw `curl /v2/databases/{id}` printed 4 DB-user
passwords into an agent transcript. Root cause = two defects in the TEXT
scrubbers (scrub_text / scrub_text_fixed_length) that let standalone JSON
scalar credential fields ("password": "<value>") egress unredacted. The
dict-walk (scrub_secrets) was always correct. These tests pin all three
paths. ALL VALUES BELOW ARE FAKE.

Park into mcp/common/ alongside test_scrub_exhaustive.py.
"""
import json
from ssproxy import scrub_secrets as S

_FAKE = "FAKEpw0R0tAtEd25charXYZ"
_URI = ("postgresql://doadmin:" + _FAKE +
        "@db.example.com:25060/defaultdb?sslmode=require")
# Shape mirrors a DO managed-DB GET / users reset_auth response.
_DO_BODY = {
    "database": {
        "connection": {"uri": _URI, "password": _FAKE, "user": "doadmin"},
        "private_connection": {"uri": _URI, "password": _FAKE},
        "users": [
            {"name": "twins", "password": "FAKEtwinsPW111"},
            {"name": "unleash", "password": "FAKEunleashPW22"},
        ],
    }
}
_NEEDLES = (_FAKE, "FAKEtwinsPW111", "FAKEunleashPW22")


def _leaks(s):
    return any(n in s for n in _NEEDLES)


def test_dictwalk_redacts_all_do_passwords():
    assert not _leaks(json.dumps(S.scrub_secrets(_DO_BODY)))


def test_scrub_text_redacts_standalone_json_password_fields():
    # Bug #1: JSON "password":"v" must bind despite the key's closing quote.
    assert not _leaks(S.scrub_text(json.dumps(_DO_BODY)))


def test_scrub_text_fixed_length_redacts_standalone_json_password_fields():
    # Bug #1 + Bug #2 (fixed-length variant redacted the label, not the value).
    out = S.scrub_text_fixed_length(json.dumps(_DO_BODY))
    assert not _leaks(out)


def test_fixed_length_preserves_byte_budget():
    raw = json.dumps(_DO_BODY)
    assert len(S.scrub_text_fixed_length(raw)) == len(raw)


def test_fixed_length_is_idempotent():
    out = S.scrub_text_fixed_length(json.dumps(_DO_BODY))
    assert S.scrub_text_fixed_length(out) == out


def test_bare_labeled_value_redacted_in_fixed_length():
    # Bug #2 regression: bare `label=value` must redact the VALUE.
    assert "FAKEbareVAL123" not in S.scrub_text_fixed_length(
        "session_secret=FAKEbareVAL123")


def test_no_overredaction_of_benign_json():
    benign = json.dumps({"passwordHash_note": "n/a",
                         "description": "resets the password on demand",
                         "count": 5})
    assert S.scrub_text(benign) == benign
