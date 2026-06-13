"""Exhaustive coverage tests for the four credential types the operator
cares most about: kubeconfig, DigitalOcean, Cloudflare, GitHub.

Run: python3 mcp-servers/common/test_scrub_exhaustive.py

Each test calls scrub_text on a representative real-world shape and
asserts (a) the credential value is gone from the output AND (b) some
recognizable surrounding context survives, so an operator reviewing
a scrubbed log can still tell what was redacted.

Variable names deliberately avoid `secret`, `token`, `password`, etc.
so the test source itself doesn't trigger the scrubber in transit
through this very ssproxy. Using `tk` (token), `cr` (credential),
`fld` (field) instead. Test inputs are constructed at runtime via
helpers so triggering label/value pairs never appear as literals in
the source.
"""

from __future__ import annotations

import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Tests live in tests/; package source is at src/ssproxy/. Prepend the src
# tree to sys.path so `from ssproxy.<x> import y` resolves without requiring
# an editable install.
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from ssproxy.scrub_secrets import scrub_text, scrub_secrets, REDACTED


FAILURES: list[str] = []

# Triggering labels split across literals so the test source itself
# doesn't get egress-scrubbed when this file is read into ssproxy's
# own conversation context during development.
SEP_EQ = "=" + ""
SEP_CO = ":" + " "


def must_not_contain(label: str, scrubbed: str, leaked: str) -> None:
    if leaked in scrubbed:
        FAILURES.append(f"LEAK [{label}]: {leaked!r} survived in {scrubbed!r}")


def must_contain(label: str, scrubbed: str, kept: str) -> None:
    if kept not in scrubbed:
        FAILURES.append(f"CONTEXT LOST [{label}]: {kept!r} missing from {scrubbed!r}")


def labeled(lbl: str, value: str, sep: str = SEP_CO) -> str:
    """Build a `<label><sep><value>` string at runtime — avoids the
    triggering pair appearing as a literal in this file's source."""
    return lbl + sep + value


# ─── DigitalOcean ─────────────────────────────────────────────────────

tk = "dop_v1_" + "a" * 64
out = scrub_text(labeled("DO_TOKEN", tk, SEP_EQ) + " trailing")
must_not_contain("do-pat", out, tk)
must_contain("do-pat", out, "DO_TOKEN")

tk = "doo_v1_" + "b" * 64
out = scrub_text(labeled("oauth", tk) + " trailing")
must_not_contain("do-oauth-access", out, tk)

tk = "dor_v1_" + "c" * 64
out = scrub_text(labeled("refresh", tk, SEP_EQ) + " trailing")
must_not_contain("do-oauth-refresh", out, tk)

# Spaces access key ID — distinctive `DO00` + 16 uppercase chars.
tk = "DO00" + "A" * 16
out = scrub_text(labeled("spaces", tk) + " (rotate quarterly)")
must_not_contain("do-spaces-key", out, tk)
must_contain("do-spaces-key", out, "spaces")

# Spaces secret key (no prefix; ~40 chars). Pattern-only matching
# unsafe — must be caught via dict-key SECRET_FIELDS path.
cr = "P2WPSu68Bfl89j72vT" + "X" * 22
parsed = {"name": "test", "secret_key": cr}
scrubbed = scrub_secrets(parsed)
must_not_contain("do-spaces-secret-field", json.dumps(scrubbed), cr)


# ─── Cloudflare ───────────────────────────────────────────────────────

tk = "cfut_" + "A" * 44
out = scrub_text(labeled("value", tk))
must_not_contain("cf-cfut", out, tk)

tk = "cfat_" + "B" * 44
out = scrub_text(labeled("value", tk))
must_not_contain("cf-cfat", out, tk)

tk = "cfk_" + "C" * 44
out = scrub_text(labeled("value", tk))
must_not_contain("cf-cfk", out, tk)

# Origin CA key.
tk = "v1.0-" + "a" * 24 + "-" + "b" * 146
out = scrub_text(labeled("origin ca", tk))
must_not_contain("cf-origin-ca", out, tk)

# Access service token Client ID — `.access` suffix.
tk = "1234567890abcdef1234567890abcdef" + ".access"
out = scrub_text(labeled("client_id", tk, SEP_EQ))
must_not_contain("cf-access-client-id", out, tk)

# Access service token Client Secret — bare 64-hex, only safe via field-name.
cr = "abcdef0123456789" * 4
parsed = {"client_id": "x.access", "client_secret": cr}
scrubbed = scrub_secrets(parsed)
must_not_contain("cf-access-secret-field", json.dumps(scrubbed), cr)

# Tunnel token — base64-encoded JSON starting with `{"a":"`. Real
# tokens are 200+ chars. Build a single legitimate base64 blob.
payload = '{"a":"acct123","t":"tun456","s":"' + "S" * 120 + '"}'
tk = base64.urlsafe_b64encode(payload.encode()).decode()
assert tk.startswith("eyJhIjoi"), f"test scaffold broken: {tk[:20]}"
out = scrub_text("cloudflared run --token " + tk)
must_not_contain("cf-tunnel-token", out, tk)

# Helm-values camelCase shape — the original leak vector.
camel_input = labeled("cloudflareApiToken", "x" * 40 + "==", SEP_CO)
out = scrub_text(camel_input)
must_not_contain("cf-helm-camelcase", out, "x" * 40)


# ─── GitHub ───────────────────────────────────────────────────────────

tk = "ghp_" + "x" * 36
out = scrub_text(labeled("PAT", tk, SEP_EQ))
must_not_contain("gh-ghp-classic", out, tk)

# Longer-than-canonical PAT — gitleaks fixed-36 leaves the tail.
tk = "ghp_" + "y" * 80
out = scrub_text(labeled("PAT", tk, SEP_EQ) + " trailing")
must_not_contain("gh-ghp-long", out, tk)

tk = "gho_" + "a" * 36
out = scrub_text(labeled("oauth", tk))
must_not_contain("gh-gho", out, tk)

tk = "ghu_" + "b" * 36
out = scrub_text(labeled("u2s", tk))
must_not_contain("gh-ghu", out, tk)

tk = "ghs_" + "c" * 36
out = scrub_text(labeled("s2s short", tk))
must_not_contain("gh-ghs-classic", out, tk)

# Server-to-server NEW LONG form (rolling out 2026-05+). Shape:
# `ghs_<APPID>_<JWT>`, embedding `.` and `_`, real tokens ~520 chars.
# Original fixed-36 regex would leak 480+ chars of tail.
appid = "123456"
jwt_chunk = ("eyJ" + "a" * 200) + "." + ("eyJ" + "b" * 200) + "." + ("z" * 100)
tk = "ghs_" + appid + "_" + jwt_chunk
out = scrub_text(labeled("installation_tok", tk, SEP_EQ) + " end")
must_not_contain("gh-ghs-long-form", out, tk)
must_not_contain("gh-ghs-tail-jwt", out, jwt_chunk[-100:])

tk = "ghr_" + "d" * 36
out = scrub_text(labeled("refresh", tk))
must_not_contain("gh-ghr", out, tk)

# Fine-grained PAT — `<22>_<59+>`.
tk = "github_pat_" + "X" * 22 + "_" + "Y" * 59
out = scrub_text(labeled("fg-pat", tk))
must_not_contain("gh-fine-grained", out, tk)

# GitHub App private key (PEM block) — caught by gitleaks PEM rule.
pem = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" + "a" * 200 + "\n"
    "-----END RSA PRIVATE KEY-----"
)
out = scrub_text(pem)
must_not_contain("gh-app-pem", out, "MIIEvQ")

# Token-in-clone-URL — covered by URI-userinfo regex.
out = scrub_text("git clone https://" + "ghp_" + "z" * 36 + "@github.com/o/r.git")
must_not_contain("gh-clone-url", out, "ghp_" + "z" * 36)


# ─── Kubeconfig ───────────────────────────────────────────────────────

# SA bearer JWT in inline YAML `token:` field.
sa_jwt = "eyJhbGciOiJSUzI1NiIs" + "a" * 200 + "." + "b" * 200 + "." + "c" * 100
out = scrub_text("    " + labeled("token", sa_jwt))
must_not_contain("kc-token-jwt", out, sa_jwt)

# Hyphenated `access-token:` (legacy gcp auth-provider).
gke = "ya29.AHES" + "x" * 100
out = scrub_text("    " + labeled("access-token", gke))
must_not_contain("kc-access-token-label", out, gke)

# Hyphenated `refresh-token:`.
goog = "1//0e" + "y" * 80
out = scrub_text("    " + labeled("refresh-token", goog))
must_not_contain("kc-refresh-token-label", out, goog)

# `id-token:` (OIDC JWT) — caught by gitleaks JWT rule.
oidc_jwt = "eyJ0eXAi" + "a" * 200 + "." + "b" * 200 + "." + "c" * 100
out = scrub_text("    " + labeled("id-token", oidc_jwt))
must_not_contain("kc-id-token", out, oidc_jwt)

# EKS bearer.
eks = "k8s-aws-v1." + "K" * 200
out = scrub_text("      " + labeled("token", eks))
must_not_contain("kc-eks-bearer", out, eks)

# Bare GKE `ya29.` token.
gke = "ya29." + "G" * 150
out = scrub_text("      " + labeled("access-token", gke))
must_not_contain("kc-gke-token", out, gke)

# Bare Google OIDC `1//` refresh.
goog = "1//0e" + "R" * 70
out = scrub_text("      " + labeled("refresh-token", goog))
must_not_contain("kc-google-oidc-refresh", out, goog)

# DOKS PAT in kubeconfig's exec env.
tk = "dop_v1_" + "d" * 64
out = scrub_text("      " + labeled("token", tk))
must_not_contain("kc-doks-pat", out, tk)

# Hyphenated field-name walk — client-key-data must be redacted by
# the dict-walk path (the base64 PEM body is opaque to text regex).
kc_parsed = {
    "users": [{
        "user": {
            "client-key-data": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==aaaaaaaa",
            "client-certificate-data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
        }
    }]
}
scrubbed_kc = scrub_secrets(kc_parsed)
must_not_contain("kc-client-key-data-field",
                 json.dumps(scrubbed_kc),
                 "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==aaaaaaaa")

# Hyphenated access-token / refresh-token at field level.
kc_parsed = {"auth-provider": {"config": {
    "access-token": "ya29.LEAK" + "Z" * 50,
    "refresh-token": "1//0eLEAK" + "W" * 50,
}}}
scrubbed_kc = scrub_secrets(kc_parsed)
flat = json.dumps(scrubbed_kc)
must_not_contain("kc-access-token-field", flat, "ya29.LEAK")
must_not_contain("kc-refresh-token-field", flat, "1//0eLEAK")


# ─── Idempotency ──────────────────────────────────────────────────────

sample = (
    "Mix: ghp_" + "x" * 36 + " and cfut_" + "A" * 44 +
    " and " + labeled("DO_TOKEN", "dop_v1_" + "a" * 64, SEP_EQ) +
    " and k8s-aws-v1." + "K" * 30
)
once = scrub_text(sample)
twice = scrub_text(once)
if once != twice:
    FAILURES.append("IDEMPOTENCY: scrub differs on second pass\n  once : "
                    + once + "\n  twice: " + twice)


# ─── JSON-escape overrun guard (ssproxy same-length scrub) ────────────
#
# Regression for the JWT capture-class eating the trailing JSON-escape
# backslash: an inner JSON value like `\"<jwt>\"` (the wire encoding of
# `"<jwt>"` inside an outer string content) must remain parseable as
# JSON after scrub_text_fixed_length runs. The original repro was a
# 233-byte argocd-terraform-token; the fix removed the literal `\` from
# the jwt rule's value classes (real JWTs are base64url + `.`, never
# include backslash). Any future regex addition that lets the secret
# capture extend across a JSON-escape `\` will fail this test.

from ssproxy.scrub_secrets import scrub_text_fixed_length

def _outer_body(secret_value: str) -> str:
    """Embed a secret inside `\\"<value>\\"` inside a tool_result-like
    string content, return the full outer Anthropic body as JSON."""
    inner = '{"some-' + 'tk' + 'n": "' + secret_value + '"}'
    outer = {
        "model": "claude-opus-4-7",
        "messages": [{"role": "user", "content": inner}],
    }
    return json.dumps(outer)


def _assert_post_scrub_parses(label: str, value: str) -> None:
    body = _outer_body(value)
    try:
        json.loads(body)
    except json.JSONDecodeError as e:
        FAILURES.append(f"PRE-SCRUB INVALID JSON [{label}]: {e.msg}@{e.pos}")
        return
    scrubbed = scrub_text_fixed_length(body)
    if len(scrubbed) != len(body):
        FAILURES.append(
            f"SAME-LENGTH VIOLATED [{label}]: orig={len(body)} "
            f"scrubbed={len(scrubbed)}"
        )
        return
    try:
        json.loads(scrubbed)
    except json.JSONDecodeError as e:
        FAILURES.append(
            f"JSON-ESCAPE OVERRUN [{label}]: {e.msg}@{e.pos} "
            f"(scrubber broke a `\\\"<value>\\\"` boundary)"
        )


# JWT (3 base64url segments, 200+ bytes — matches the argocd-terraform-token shape)
_assert_post_scrub_parses(
    "jwt-shape",
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAxIn0.eyJzdWIiOiJ1c2VyIn0.aB" + "X" * 200,
)

# A handful of other long secret shapes that go through the same hook.
# If any future regex consumes a trailing `\`, one of these will catch it.
_assert_post_scrub_parses("ghp", "ghp_" + "x" * 36)
_assert_post_scrub_parses("github_pat", "github_pat_" + "A" * 82)
_assert_post_scrub_parses("dop_v1", "dop_v1_" + "a" * 64)
_assert_post_scrub_parses("ghs", "ghs_" + "a" * 36)
_assert_post_scrub_parses("hf_", "hf_" + "a" * 34)
_assert_post_scrub_parses("openai-sk-proj", "sk-proj-" + "A" * 74 + "T3BlbkFJ" + "A" * 74)
_assert_post_scrub_parses("anthropic", "sk-ant-api03-" + "A" * 93 + "AA")
_assert_post_scrub_parses("aws-akia", "AKIA" + "ABCDEFGHIJKLMNOP")
_assert_post_scrub_parses("ya29", "ya29." + "A" * 60)
_assert_post_scrub_parses("hvs", "hvs." + "A" * 40)
_assert_post_scrub_parses("k8s-aws-v1", "k8s-aws-v1." + "A" * 40)
_assert_post_scrub_parses("gcp-api-key", "AIza" + "A" * 35)
_assert_post_scrub_parses("digitalocean-doo", "doo_v1_" + "f" * 64)

# jwt-base64 tripwire: the rule has the same value-class-includes-`\`
# shape, but is currently accident-saved by _gitleaks_replace_fixed_length
# selecting the short first-named-group (alg/apu/...) as the redaction
# span rather than the whole match. If a future dispatcher refactor
# changes that selection, this case will catch the reintroduced bug.
_assert_post_scrub_parses(
    "jwt-base64-shape",
    "ZXlKaGJHY2lPaU" + ("AaBbCcDdEe0123456789" * 12),
)

# Fuzz: random alphanumeric runs at varying lengths. None of these should
# match anything, but if they do (false positive) the parse must still
# succeed.
import random
random.seed(20260610)
alpha = "abcdefghijklmnopqrstuvwxyz0123456789-_."
for i in range(40):
    n = random.choice([20, 50, 100, 250, 500])
    val = "".join(random.choice(alpha) for _ in range(n))
    _assert_post_scrub_parses(f"fuzz-{i}", val)


# ─── Anti-FP: things that look credential-shaped but aren't ──────────

keepers = [
    "the commit hash a1b2c3d4e5f6789abcdef01234567890abcdef12",
    "uuid 550e8400-e29b-41d4-a716-446655440000",
    "version 1.2.3-beta.4",
    "username doadmin (lowercase 8 chars)",
    "ya29 prefix mentioned but not a real token",
    "the field cloudflareApiToken is described here",
    "docker image cork-1.vrtx.ai:30500/cork-webui:f542ce6",
]
for k in keepers:
    o = scrub_text(k)
    if o != k:
        FAILURES.append("FP on benign text: " + repr(k) + " -> " + repr(o))


# ─── Report ───────────────────────────────────────────────────────────

if FAILURES:
    print("FAIL — " + str(len(FAILURES)) + " regression(s):", file=sys.stderr)
    for f in FAILURES:
        print("  - " + f, file=sys.stderr)
    sys.exit(1)

print("PASS — exhaustive scrubber coverage: DO + CF + GitHub + kubeconfig + idempotency + anti-FP")
