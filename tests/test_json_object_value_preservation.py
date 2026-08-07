"""Regression test for 2026-08-07 cork pe-9 400 incident.

The `_LABELED_SECRET` value class excluded `}` but not `{`. Applied to
JSON-schema fragments like:

    "pageToken":{"description":"The page token to use for pagination."}

the regex matched `Token":{` (label=`Token`, value=`{`) and replaced
the sole `{` with `*`, corrupting the JSON:

    "pageToken":*"description":"The page token to use for pagination."

Anthropic's API rejected the resulting body with
`invalid_request_error: unexpected character` at exactly the byte
position of the mangled `{`. Because tool-schemas ride along with
every /v1/messages request, every agent whose session included the
Google Drive MCP schemas failed 100% of the time.

Fix: add `{` to the value character class so an opening brace can
never be captured as a "secret value" — nested JSON objects are
already-structured content, not scalar secrets.
"""

from ssproxy.scrub_secrets import scrub_text_fixed_length


def test_json_object_after_labeled_key_is_not_corrupted():
    body = (
        '{"properties":{'
        '"pageToken":{"description":"The page token to use for pagination.","type":"string"},'
        '"pageSize":{"description":"How many.","type":"integer"}'
        '}}'
    )
    scrubbed = scrub_text_fixed_length(body)
    assert scrubbed == body, (
        "opening `{` at a labeled-key value position must not be redacted — "
        f"got {scrubbed!r}"
    )


def test_json_object_after_various_labeled_keys():
    for label in ["token", "secret", "password", "api_key", "auth_token", "bearer"]:
        body = f'{{"{label}":{{"description":"nested schema","type":"string"}}}}'
        scrubbed = scrub_text_fixed_length(body)
        assert scrubbed == body, (
            f"label={label!r}: opening `{{` at value position was mangled "
            f"→ {scrubbed!r}"
        )


def test_scalar_secret_value_still_redacted():
    body = '{"token":"sk_live_abc12345XYZ","other":"ok"}'
    scrubbed = scrub_text_fixed_length(body)
    assert scrubbed != body, "labeled scalar secret must still be redacted"
    assert "sk_live_abc12345XYZ" not in scrubbed
    assert "REDACT" in scrubbed
    assert len(scrubbed) == len(body), "same-length invariant"
