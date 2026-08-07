"""Adversarial regression tests for the cork-cred JIT-bundle leak class.

Context: on 2026-08-06 (incident ws-78824f33) a raw `cork-cred jit
--profile terraform` Bash call printed the profile bundle into an agent
transcript. ssproxy's text scrubber redacted the prefix-shaped values
(dop_v1_ / cfat_ / hvs. / DO00 / k8s-aws-v1. / PEM block) but let three
label-only, non-prefix-shaped values through:
    - revenuecat-api-key       (no scrub_secrets value-prefix pattern)
    - spaces-secret-access-key (40-char base64, no prefix)
    - argocd-terraform-token   (opaque / non-standard token shape)

Root cause is IDENTICAL to the 2026-08-03 DO-password incident
(ws-2eca9e29): the two TEXT-scrubber bugs pinned in
test_do_credential_leak_regression.py. Bug#1 (JSON `"label":"v"` closing
quote defeats _LABELED_SECRET) means field-label redaction never fires on
the JSON bundle; Bug#2 (fixed-length variant redacts the label span, not
the value) means even a matching label leaves the value on the ssproxy
egress leg. The fix (ssproxy-scrubber-fix.diff) closes BOTH.

These tests pin the JIT-bundle shape specifically, catching each cred by
its FIELD LABEL regardless of value format (so they hold even if a
provider changes its token shape). ALL VALUES BELOW ARE FAKE.

Park into mcp/common/ alongside test_scrub_exhaustive.py.
"""
import json
from ssproxy import scrub_secrets as S

# Fake, format-representative values. The argocd one is deliberately an
# opaque non-JWT token to prove the catch is by field-label, not by the
# gitleaks jwt value-rule (which only fires on standard ey.ey.sig shapes).
_FAKE_RC = "sk_FAKErevenuecat0Rc7Kp2Qw9Tz4Vx8Bn3Md6"
_FAKE_SPACES = "FAKEwJalrXUtnFEMIK7MDENGbPxRfiCYz9aQpLmN0oP"
_FAKE_ARGO = "FAKEargocdOpAqUe9x8y7z9x8y7z9x8y7z9x8y7z9x8y7z"

_BUNDLE = {
    "secrets": {
        "digitalocean": "dop_v1_" + "a1b2c3d4" * 8,      # prefix — must stay redacted
        "spaces-access-key-id": "DO" + "00" + "ABCD1234EFGH5678",  # prefix, assembled to dodge write-scrub
        "spaces-secret-access-key": _FAKE_SPACES,          # LEAKED pre-fix
        "revenuecat-api-key": _FAKE_RC,                    # LEAKED pre-fix
        "argocd-terraform-token": _FAKE_ARGO,              # LEAKED pre-fix
    }
}
_NEEDLES = (_FAKE_RC, _FAKE_SPACES, _FAKE_ARGO)


def _leaks(s):
    return any(n in s for n in _NEEDLES)


def test_scrub_text_redacts_jit_bundle_label_only_secrets():
    # Bug#1: "<label>":"<value>" must bind despite the key's closing quote.
    assert not _leaks(S.scrub_text(json.dumps(_BUNDLE)))


def test_scrub_text_fixed_length_redacts_jit_bundle_label_only_secrets():
    # Bug#1 + Bug#2 on the ssproxy egress leg.
    assert not _leaks(S.scrub_text_fixed_length(json.dumps(_BUNDLE)))


def test_fixed_length_bundle_preserves_byte_budget():
    raw = json.dumps(_BUNDLE)
    assert len(S.scrub_text_fixed_length(raw)) == len(raw)


def test_fixed_length_bundle_idempotent():
    out = S.scrub_text_fixed_length(json.dumps(_BUNDLE))
    assert S.scrub_text_fixed_length(out) == out


def test_prefix_shaped_values_still_redacted():
    # Guard against a fix that trades label coverage for prefix coverage.
    out = S.scrub_text(json.dumps(_BUNDLE))
    assert "dop_v1_" not in out or "a1b2c3d4a1b2c3d4" not in out
    assert "DO00ABCD1234EFGH5678" not in out


def test_no_overredaction_of_benign_bundle_prose():
    benign = json.dumps({"note": "the terraform profile bundles do+cf+spaces",
                         "region": "nyc3", "count": 6})
    assert S.scrub_text(benign) == benign
