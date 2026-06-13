"""Recursive credential scrubber for MCP tool responses.

WHY
---
Tool output lands in conversation context, which is sent to the LLM
provider's API. Putting a raw secret VALUE in a tool result = leaking
the secret. Several upstream APIs we wrap (DigitalOcean managed DBs,
ArgoCD repo creds, Unleash secret context fields, Terraform state
outputs marked sensitive, etc.) return plaintext credentials in their
ordinary responses.

This module is the single place those fields get redacted before they
leave the MCP. Defense in depth: applied at the response boundary,
not at each tool call site, so a tool that forgets to wrap can't open
a fresh leak path.

WHEN NOT TO USE
---------------
Don't use this on MCPs whose whole purpose is to RETURN secret values
(e.g. the vault MCP — secret retrieval is the entire job). Those MCPs
need a different protection model (operator pipes the value via
`cork-cred jit` rather than tool-call return).

PUBLIC SURFACE
--------------
Two text-level scrub variants live here:

  ``scrub_text(s)``                — variable-length replacement, marker
                                     defaults to ``[REDACTED]``. Used by
                                     MCP response scrubbing, the
                                     graphiti ingester, and worker
                                     bundle scrubbing
                                     (``lib/cork_credential_scrubber.py``).
                                     Readability beats byte-count for
                                     these consumers.

  ``scrub_text_fixed_length(s)``   — same-length replacement using the
                                     ``fixed_length_redaction`` tier
                                     ladder. Used exclusively by
                                     ssproxy's egress request hook so
                                     Content-Length stays pristine and
                                     the wire-format never changes.
"""

from __future__ import annotations

import re
import urllib.parse

try:
    from .gitleaks_patterns import GITLEAKS_PATTERNS
except ImportError:  # standalone script usage (not as package)
    from gitleaks_patterns import GITLEAKS_PATTERNS


# Field names whose value is always a raw secret. Lower-cased compare,
# matched as the exact dict key (not substring) — `key` won't match,
# but `api_key` will.
SECRET_FIELDS = frozenset({
    "password",
    "secret",
    "token",
    "private_key",
    "client_secret",
    "auth_token",
    "access_key",
    "secret_key",
    "ssh_key",
    "cert_key",
    "api_key",
    "passphrase",
    "ca_certificate",  # not a secret in the SSL-trust sense, but
                        # routinely conflated with private material —
                        # redact to be safe; operator pulls via
                        # provider CLI if needed.
    "encryption_key",
    "session_token",
    "refresh_token",
    "bearer_token",
    "webhook_secret",
    "signing_key",
    "encryption_secret",
    # Kubeconfig — hyphenated forms are exact-match-required since
    # frozenset compares the whole key. Cover both for parity with the
    # YAML inline-string path (`_LABELED_SECRET` handles those).
    "client-key-data",
    "client-key",
    "access-token",
    "refresh-token",
    "id-token",
    "id_token",
    # DigitalOcean / Cloudflare R2 / generic S3-shaped credentials
    # surfaced by their respective `*keys list` endpoints.
    "access_key_id",
    "secret_access_key",
    # AWS SDK JSON uses Pascal-case; the dict-walk lowercases keys
    # before comparing, so both `secret_access_key` and the Pascal
    # `SecretAccessKey` → `secretaccesskey` form need entries.
    "secretaccesskey",
    "accesskeyid",
    # Docker registry config — `auths.<registry>.auth` is base64 of
    # `<user>:<pat>`. Once base64 we can't pattern-match the inner
    # token, so redact the whole base64 blob at the field level.
    "auth",
})

# Field names that hold a URI which may have inline userinfo (user:pass@).
URI_FIELDS = frozenset({
    "uri",
    "private_uri",
    "connection_string",
    "connection_uri",
    "repo_url",        # ArgoCD repos may embed https://user:pass@github.com/...
    "repository_url",
})

REDACTED = "[REDACTED]"


def fixed_length_redaction(n: int) -> str:
    """Return a redaction marker of EXACTLY ``n`` bytes.

    Picks the longest recognizable label that fits within ``n`` and
    right-pads with ``*`` to reach the target length. The tier
    ladder is intentionally compact so a brief inline secret (e.g. a
    20-char access-key id) still renders something a human can scan,
    while longer matches get the verbose ssproxy banner.

    Used by ``scrub_text_fixed_length`` (which is consumed only by
    ssproxy's egress-body scrubber). The standard variable-length
    ``REDACTED`` marker is preferable everywhere else — same-length
    redaction is a wire-format optimization for the proxy, not a
    readability win for log/transcript consumers.
    """
    if n >= 21:
        return "[REDACTED BY SSPROXY]" + "*" * (n - 21)
    if n >= 13:
        return "[REDACTPROXY]" + "*" * (n - 13)
    if n >= 10:
        return "[REDACTED]" + "*" * (n - 10)
    if n >= 7:
        return "[RDCTD]" + "*" * (n - 7)
    return "*" * n


def scrub_uri(s: str) -> str:
    """Strip user:password@ from a URL, preserve scheme + host + port.

    Returns the input unchanged on parse failure or when no userinfo
    is present.
    """
    if not isinstance(s, str):
        return s
    try:
        p = urllib.parse.urlparse(s)
    except Exception:
        return s
    if not p.scheme or "@" not in (p.netloc or ""):
        return s
    host = p.hostname or ""
    netloc = f"{REDACTED}@{host}"
    if p.port:
        netloc += f":{p.port}"
    return urllib.parse.urlunparse(p._replace(netloc=netloc))


# ─── Text-level scrubbing ─────────────────────────────────────────────
#
# For MCPs whose tool output is unstructured text (tofu plan/state,
# argocd app manifests rendered as YAML, log lines), the field-name
# scrubber can't catch inline credentials. These regex patterns match
# the common shapes: known token prefixes, key=value pairs labeled
# with a secret-y name, and bearer headers.

# Provider token prefixes — public, well-known, safe to pattern-match.
# Each is anchored to a non-word boundary so a longer string that
# happens to contain the prefix as a substring doesn't get redacted.
_TOKEN_PATTERNS = [
    # ─── DigitalOcean ─────────────────────────────────────────────
    # Personal Access Token (v1). Body is 64-char lowercase hex per
    # DO's docs; we keep the charset case-insensitive defensively and
    # the quantifier greedy so longer-than-canonical bodies still match
    # whole.
    re.compile(r"\bdop_v1_[A-Fa-f0-9]{40,}\b"),
    # DigitalOcean OAuth access + refresh tokens. Same shape family as
    # the PAT, distinct prefixes. gitleaks has fixed-64 entries for
    # both but no greedy cork pre-pass — adding here so a longer body
    # gets consumed whole (mirroring the `dop_v1_` handling).
    re.compile(r"\bdoo_v1_[A-Fa-f0-9]{40,}\b"),
    re.compile(r"\bdor_v1_[A-Fa-f0-9]{40,}\b"),
    # DigitalOcean Spaces access key ID. Distinctive `DO00` prefix +
    # 16 uppercase alphanumeric chars (20 total). Surfaces in
    # `doctl spaces keys list` output. Not covered by any gitleaks
    # entry as of the snapshot we lifted.
    re.compile(r"\bDO00[A-Z0-9]{16}\b"),

    # ─── GitHub ───────────────────────────────────────────────────
    # Classic Personal Access Token. Body is 36 base62 chars (incl.
    # 6-char CRC32 checksum); greedy `{36,251}` to track GitHub's
    # documented 255-char ceiling (see token-format docs).
    re.compile(r"\bghp_[A-Za-z0-9]{36,251}\b"),
    # OAuth access token. Was fixed-36 in gitleaks; add cork greedy.
    re.compile(r"\bgho_[A-Za-z0-9]{36,251}\b"),
    # GitHub App user-to-server token.
    re.compile(r"\bghu_[A-Za-z0-9]{36,251}\b"),
    # GitHub App server-to-server / installation token. CRITICAL: the
    # new long-form `ghs_<APPID>_<JWT>` shape (rolling out 2026-05+)
    # embeds an `_` separator and `.` (JWT delimiters) in the body
    # AND can run up to ~520 chars. The original fixed-36 gitleaks
    # entry leaks ~480 chars of tail. Charset includes `_` and `.`.
    re.compile(r"\bghs_[A-Za-z0-9_.]{36,560}\b"),
    # GitHub App refresh token.
    re.compile(r"\bghr_[A-Za-z0-9]{36,251}\b"),
    # Fine-grained Personal Access Token. Body is `[A-Za-z0-9]{22}_[A-Za-z0-9]{59,}`
    # — exactly one internal underscore at offset 22, then 59+ base62
    # (incl. 6-char CRC32). Greedy on the tail.
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),

    # ─── AWS + Kubernetes-on-cloud exec credentials ───────────────
    # AWS access key id (paired with secret; redact the id too so the
    # operator's awareness is anchored on the redaction line).
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # EKS / aws-iam-authenticator exec bearer — kubectl on EKS
    # presents `k8s-aws-v1.<base64-presigned-sts>` as the bearer
    # token in `kubectl config view --raw` output and in any
    # ExecCredential JSON the wrapper prints. No gitleaks entry.
    re.compile(r"\bk8s-aws-v1\.[A-Za-z0-9_\-]{20,}\b"),
    # GKE / Google OAuth access token. `ya29.<base64>`. Surfaces in
    # `gcloud auth print-access-token` and in legacy gcp auth-provider
    # kubeconfigs (`auth-provider.config.access-token`).
    re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}\b"),
    # Google OIDC refresh token (legacy gcp auth-provider). Prefix
    # `1//` followed by URL-safe base64. Catches the
    # `auth-provider.config.refresh-token` field.
    re.compile(r"\b1//[A-Za-z0-9_\-]{40,}\b"),

    # ─── HashiCorp Vault ──────────────────────────────────────────
    # Vault root/service tokens (legacy `s.` and modern `hvs.`).
    re.compile(r"\bs\.[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bhvs\.[A-Za-z0-9_\-]{24,}\b"),

    # ─── Cloudflare ───────────────────────────────────────────────
    # Cloudflare's 2026 scannable-token formats. All three share the
    # same body shape: 40-char URL-safe base64 + CRC32 checksum
    # suffix. Greedy `{40,}` so any future length extension still
    # gets consumed whole.
    re.compile(r"\bcfut_[A-Za-z0-9_\-]{40,}\b"),   # User API token
    re.compile(r"\bcfat_[A-Za-z0-9_\-]{40,}\b"),   # Account-scoped API token
    re.compile(r"\bcfk_[A-Za-z0-9_\-]{40,}\b"),    # Global API key (new)
    # Cloudflare Access service token Client ID. Distinctive `.access`
    # suffix on a 32-hex blob makes prefix-matching trivially safe
    # (no collision with bare SHA-256 / MD5).
    re.compile(r"\b[a-f0-9]{32}\.access\b"),
    # Cloudflare Tunnel token (cloudflared `--token`). Base64-encoded
    # JSON `{"a":"<acct>","t":"<tunnel>","s":"<secret>"}`. The
    # base64-encoding of the literal `{"a":"` prefix is `eyJhIjoi`,
    # a near-perfect content anchor. No prefix-only-CF formats use
    # this preamble.
    re.compile(r"\beyJhIjoi[A-Za-z0-9+/_\-]{100,}={0,2}\b"),
    # NB: Cloudflare legacy 40-char alphanumeric API tokens (pre-2026,
    # no prefix) and legacy 37-char hex Global Key have no safe
    # pattern-only regex — they collide with SHA-1, commit hashes,
    # and every other hex/alphanumeric identifier. Mitigations: the
    # labeled-secret regex (`cloudflareApiToken=[REDACTED BY SSPROXY]) + SECRET_FIELDS
    # dict-walk handle the structured cases; bare hex/alphanumeric in
    # free text is unrecoverable without context. Operator should
    # rotate any pre-2026 CF tokens.
]

# `<label>(=|:|space):? <value>` where label is one of the secret-y
# words. The value is anything up to whitespace, comma, quote, or end.
#
# No leading `\b` on purpose — operator helm values + many YAMLs use
# CamelCase keys like `cloudflareApiToken:` / `webhookSecret:`. Python
# regex `\b` only fires at word/non-word transitions, so `\bToken`
# never matches mid-word (`i` and `T` are both word chars). Dropping
# `\b` lets the label match suffixes inside CamelCase identifiers
# while still requiring `\s*[:=]` immediately after — so substrings
# inside words without a trailing `:=` (e.g. `passwordhash`) don't
# get touched. The trailing `=` in the replacement format collapses
# back to a sane shape: input `cloudflareApiToken: cfut_xxx` becomes
# `cloudflareApiToken=[REDACTED]`.
_LABELED_SECRET = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|client[_-]?secret|"
    r"auth[_-]?token|access[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|bearer[_-]?token|secret[_-]?key|private[_-]?key|"
    r"client[_-]?key(?:[_-]data)?|webhook[_-]?secret|signing[_-]?key|"
    r"connection[_-]?string|passphrase|encryption[_-]?key|bearer)"
    r"\s*[:=]\s*"
    # Value class excludes `[` and `]` too so a previously-scrubbed
    # `[REDACTED]` token doesn't get re-matched on a second pass and
    # turned into `[REDACTED]]`. Keeps the scrubber idempotent.
    #
    # ALSO excludes the literal backslash. JSON strings escape inner
    # quotes as `\"`, so a body like `"token":"abc\"def"` would
    # otherwise let the value class straddle the escape pair, capture
    # `abc\`, and emit a same-length replacement that orphans the
    # quote's escape target — corrupting the JSON. Stopping the value
    # at the first `\` keeps every match an "intact run of value
    # bytes" with no half-escapes inside.
    r"['\"]?([^\s,'\")\[\]\}\\]+)['\"]?",
    re.IGNORECASE,
)

# `Authorization: Bearer xxx` / `Authorization: Basic xxx`.
_AUTH_HEADER = re.compile(
    r"(Authorization:\s*(?:Bearer|Basic|Token))\s+([A-Za-z0-9._\-+/=]+)",
    re.IGNORECASE,
)

# Inline URI userinfo — `scheme://user:password@host[:port]`. Catches
# tofu plan/state lines that print connection strings inline.
_URI_USERINFO = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)"
    r"(?P<user>[^\s:/@]+):"
    r"(?P<password>[^\s@/]+)@"
)

# Single-token URI userinfo — `scheme://TOKEN@host`, no colon. This is
# how GitHub PATs (and several other forge auths) are typically
# embedded in clone URLs:
#
#   https://ghp_AAA...@github.com/babyops-app/cork
#   https://github_pat_XXX...@github.com/owner/repo.git
#   https://oauth2:TOKEN@gitlab.example.com    ← caught by _URI_USERINFO
#   https://x-access-token:TOKEN@github.com    ← caught by _URI_USERINFO
#
# The two colon-pair forms are handled by `_URI_USERINFO` above; this
# pattern picks up the single-component form (no colon between user
# and `@`), which the original pattern misses entirely.
#
# We redact the WHOLE userinfo blob (anything between scheme and `@host`)
# regardless of token prefix / length / character class — defense in
# depth, since the operator's existing token-prefix regexes are
# fixed-length (gitleaks patterns are 36 / 82 exact) and a longer token
# would leak its trailing chars when matched via the prefix path. By
# redacting the userinfo as a unit BEFORE the prefix patterns run, we
# get a clean `[REDACTED]@host` regardless of what token shape ended
# up in the URL — including legacy 40-char-hex tokens with no prefix.
#
# Trade-off: a legitimate `https://username@example.com` (basic-auth
# username only, no credential) also gets redacted. That's a safe
# failure mode for a scrubber whose job is to prevent egress leaks —
# better to over-redact than to leak.
_URI_USERINFO_NOPASS = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)"
    r"(?P<userinfo>[^\s/@]+)"
    r"@(?P<host>[A-Za-z0-9.\-]+(?::\d+)?)"
)


# Compile gitleaks patterns once at module load. Each entry is
# (compiled_pattern, rule_id). Iteration order = file order, which
# matches gitleaks' own ordering — deterministic.
_GITLEAKS_COMPILED: list[tuple[re.Pattern, str]] = [
    (re.compile(rx), rid) for rx, rid in GITLEAKS_PATTERNS
]


def _gitleaks_replace(m: re.Match) -> str:
    """Replace the secret portion while preserving boundary anchors.

    Most gitleaks regexes shape like `\\b(SECRET)(?:[anchor]|\\Z)` —
    capture group 1 is the secret and the trailing non-capture group
    is just a boundary check. Replacing only group 1 keeps the
    boundary character (often a quote/semicolon) in the output, which
    matters when the surrounding text is JSON/YAML and chopping the
    quote would corrupt the document.

    Patterns without a capture group (e.g. `ghp_[0-9a-zA-Z]{36}`) have
    the secret as the whole match — replace wholesale.
    """
    if m.lastindex is None or m.lastindex < 1:
        return REDACTED
    full = m.group(0)
    abs_start = m.start()
    # Use the first capture group as "the secret"; for multi-group
    # patterns (e.g. curl-auth-header) the first non-empty group is
    # the value, fall through to wholesale replacement if none found.
    secret_group = None
    for i in range(1, m.lastindex + 1):
        if m.group(i):
            secret_group = i
            break
    if secret_group is None:
        return REDACTED
    s_start = m.start(secret_group) - abs_start
    s_end = m.end(secret_group) - abs_start
    return full[:s_start] + REDACTED + full[s_end:]


def scrub_text(s: str) -> str:
    """Redact secret-shaped substrings in arbitrary text.

    Four layers, in order:
      0. URI userinfo (`scheme://userinfo@host`, both colon-pair and
         single-token forms). Runs FIRST so the userinfo is redacted
         as a clean unit. Defeats partial-match residue inside URLs
         and catches tokens with no prefix at all (legacy 40-char-hex
         OAuth tokens).
      1. Cork's GREEDY token-prefix patterns (`\\bghp_[A-Za-z0-9]{36,}\\b`
         etc.). Run BEFORE gitleaks so longer-than-typical tokens get
         consumed whole — gitleaks's fixed-length patterns (`ghp_[36]`,
         `github_pat_\\w{82}`) would otherwise eat the first N chars and
         leave the trailing chars behind as a partial leak. With cork
         going first, the greedy `{N,}` quantifier handles real-world
         tokens that exceed the typical length.
      2. Gitleaks-derived prefix/format patterns (~119 modern provider
         tokens). Catches anything cork doesn't have an explicit greedy
         pattern for (most non-github providers).
      3. Cork's original heuristics for labeled `password=xxx`, bearer
         auth headers, etc.

    Idempotent — `[REDACTED]` doesn't match any of the patterns.
    """
    if not isinstance(s, str):
        return s
    out = s
    # URI userinfo FIRST — wholesale redaction of anything between
    # scheme and @host, regardless of inner token shape. Order: colon-
    # pair form first (preserves the `user` half so an operator
    # reading scrubbed output can still see the username), then the
    # single-component form for everything else (token-only embeds).
    out = _URI_USERINFO.sub(
        lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}@", out
    )
    out = _URI_USERINFO_NOPASS.sub(
        lambda m: f"{m.group('scheme')}{REDACTED}@{m.group('host')}", out
    )
    # Greedy cork patterns BEFORE gitleaks. Both target overlapping
    # token shapes (`ghp_`, `github_pat_`, etc.); cork's are `{N,}`
    # quantifiers that consume the whole token, gitleaks's are exact
    # fixed-length and would leave the tail as a partial leak.
    for pat in _TOKEN_PATTERNS:
        out = pat.sub(REDACTED, out)
    for pat, _rid in _GITLEAKS_COMPILED:
        out = pat.sub(_gitleaks_replace, out)
    out = _LABELED_SECRET.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    out = _AUTH_HEADER.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    return out


# ─── Same-length scrubbing (ssproxy egress only) ──────────────────────
#
# ssproxy's request-body scrubber runs over raw bytes in the request
# leg and forwards them upstream. Variable-length replacement would
# force a Content-Length recompute (or chunked re-framing) on every
# scrub, which both bloats the wire (every match changes the body
# length by a different amount) and gives Anthropic / OpenAI / etc.
# a needless behavioural fingerprint. The fixed-length variant lets
# the scrubber be a pure byte-for-byte regex substitution — same
# Content-Length, same TLS record layout, no body-mutation side
# effects beyond the redacted characters themselves.
#
# Only the ssproxy addon calls these helpers. Every other consumer
# (graphiti ingest, worker bundle scrubbing per
# ``lib/cork_credential_scrubber.py``, MCP response scrub) keeps using
# the variable-length ``REDACTED`` marker via ``scrub_text`` — where
# log/transcript readability beats byte-count preservation.


def _gitleaks_replace_fixed_length(m: "re.Match") -> str:
    """Same shape as ``_gitleaks_replace`` but emits a same-length
    redaction over the secret span (preserving the surrounding
    boundary anchor chars verbatim)."""
    if m.lastindex is None or m.lastindex < 1:
        full = m.group(0)
        return fixed_length_redaction(len(full))
    full = m.group(0)
    abs_start = m.start()
    secret_group = None
    for i in range(1, m.lastindex + 1):
        if m.group(i):
            secret_group = i
            break
    if secret_group is None:
        return fixed_length_redaction(len(full))
    s_start = m.start(secret_group) - abs_start
    s_end = m.end(secret_group) - abs_start
    span = s_end - s_start
    return full[:s_start] + fixed_length_redaction(span) + full[s_end:]


def scrub_text_fixed_length(s: str) -> str:
    """Same scrub layers as ``scrub_text`` but each replacement is the
    same byte-length as the original match.

    Intended for byte-stream scrubbing where Content-Length must not
    change (ssproxy's egress request hook). Don't use elsewhere — the
    ``*``-padding hurts readability for log/transcript consumers.

    Idempotent — every tier of the replacement marker starts with
    ``[`` and ends with ``*`` or ``]``, none of which match any of the
    secret-shape regexes (they all anchor on word/character-class
    starts that don't include ``[``/``*``).
    """
    if not isinstance(s, str):
        return s
    out = s
    # URI userinfo: the colon-pair form preserves the user half and
    # only redacts the password. The same-length version expands the
    # marker to fill the whole `<user>:<password>` span — we lose the
    # user-half visibility, but the byte budget is exactly what was
    # between scheme and `@host`. Single-component form is a clean
    # span-fill already.
    def _uri_pair(m: "re.Match") -> str:
        # The matched span is `<scheme><user>:<pw>@`. Replace the
        # `<user>:<pw>` portion (between scheme-end and `@`) with a
        # same-length marker.
        prefix = m.group("scheme")
        user = m.group("user")
        pw = m.group("password")
        span = len(user) + 1 + len(pw)  # +1 for the colon
        return f"{prefix}{fixed_length_redaction(span)}@"

    def _uri_solo(m: "re.Match") -> str:
        prefix = m.group("scheme")
        userinfo = m.group("userinfo")
        host = m.group("host")
        return f"{prefix}{fixed_length_redaction(len(userinfo))}@{host}"

    out = _URI_USERINFO.sub(_uri_pair, out)
    out = _URI_USERINFO_NOPASS.sub(_uri_solo, out)

    for pat in _TOKEN_PATTERNS:
        out = pat.sub(lambda m: fixed_length_redaction(len(m.group(0))), out)
    for pat, _rid in _GITLEAKS_COMPILED:
        out = pat.sub(_gitleaks_replace_fixed_length, out)

    # Labeled secret: keep the label + `=` and replace the value with
    # a same-length marker. The original ``scrub_text`` collapses any
    # quoting around the value into a bare `<label>=<REDACTED>`; we
    # preserve the FULL original match length here so the byte budget
    # stays intact. The label half + `=` are emitted verbatim; the
    # value span (including any surrounding quotes) is replaced with
    # a same-length marker.
    def _labeled(m: "re.Match") -> str:
        full = m.group(0)
        abs_start = m.start()
        v_start = m.start(1) - abs_start
        v_end = m.end(1) - abs_start
        # Preserve `<label>` + `=` + whatever sat between (whitespace,
        # quote opener). Replace only the captured value span.
        return full[:v_start] + fixed_length_redaction(v_end - v_start) + full[v_end:]

    out = _LABELED_SECRET.sub(_labeled, out)

    def _auth(m: "re.Match") -> str:
        full = m.group(0)
        abs_start = m.start()
        v_start = m.start(2) - abs_start
        v_end = m.end(2) - abs_start
        return full[:v_start] + fixed_length_redaction(v_end - v_start) + full[v_end:]

    out = _AUTH_HEADER.sub(_auth, out)
    return out


def scrub_secrets(obj, extra_secret_fields=None, extra_uri_fields=None):
    """Recursively redact known-secret fields in dicts/lists.

    Returns a NEW structure; does not mutate input. Safe to call on
    already-scrubbed objects (idempotent).

    extra_secret_fields / extra_uri_fields let a specific MCP add
    provider-specific names (e.g. ArgoCD's `sshPrivateKey`) without
    polluting the shared list.
    """
    sf = SECRET_FIELDS if not extra_secret_fields else (
        SECRET_FIELDS | frozenset(s.lower() for s in extra_secret_fields)
    )
    uf = URI_FIELDS if not extra_uri_fields else (
        URI_FIELDS | frozenset(s.lower() for s in extra_uri_fields)
    )

    def walk(o):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                kl = k.lower() if isinstance(k, str) else None
                if kl in sf:
                    out[k] = REDACTED
                elif kl in uf and isinstance(v, str):
                    out[k] = scrub_uri(v)
                else:
                    out[k] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(x) for x in o]
        return o

    return walk(obj)
