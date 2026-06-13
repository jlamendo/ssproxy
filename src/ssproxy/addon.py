"""yolocage ssproxy mitmproxy addon — egress credential scrubber.

Sits between the in-cage agent and the LLM provider. For every HTTPS
request to a known LLM host (see ``LLM_HOSTS``), it runs a byte-stream
regex scrubber over the JSON request body and replaces any matched
credential-shaped string with a same-length redaction marker before
forwarding.

This is yolocage's safety net for "I accidentally cat'd .env into
context" — once a secret is in the conversation history, hooks can't
reach it; the request hook here is the last chance to strip it before
it leaves the cage.

The auth header (Bearer/x-api-key) passes through untouched: yolocage's
threat model is unintentional leakage in the BODY, not the LLM
credential itself.

This file is a stripped-down fork of cork's ssproxy addon — same
scrubber library (the ssproxy/scrub_secrets.py upstream), minus
cork-specific OAuth synth + signed-thinking-preservation hooks.

EXTENSIONS
----------
``SSPROXY_EXTENSIONS`` env var optionally names a JSON file with
extra regex patterns to add to the scrubber. The file is loaded once
at addon startup; format matches gitleaks's pattern shape:

    [
      {"id": "acme-token", "regex": "\\bACME_[A-Z0-9]{32}\\b"}
    ]
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from typing import Any

from mitmproxy import http, ctx

# scrub_secrets is shipped at the same dir as this file. mitmproxy puts
# the addon's directory on sys.path before loading.
import scrub_secrets
scrub_secrets.REDACTED = "[REDACTED BY SSPROXY]"
from scrub_secrets import scrub_text_fixed_length  # noqa: E402

LLM_HOSTS: frozenset[str] = frozenset({
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.deepseek.com",
    "api.x.ai",
    "api.cohere.com",
    "api.mistral.ai",
})


def _load_extensions() -> int:
    """Load SSPROXY_EXTENSIONS into scrub_secrets's compiled list.

    Each entry: {"id": "<name>", "regex": "<pattern>"}.

    Returns the count of patterns loaded. Failures are logged but do
    NOT prevent addon load — yolocage prefers degraded scrubbing over
    no scrubbing at all.
    """
    path = os.environ.get("SSPROXY_EXTENSIONS")
    if not path:
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"[ssproxy] failed to load extensions from {path}: {e}\n")
        return 0
    if not isinstance(data, list):
        sys.stderr.write(f"[ssproxy] extensions file {path} is not a JSON array\n")
        return 0
    added = 0
    for entry in data:
        if not isinstance(entry, dict):
            continue
        rule_id = entry.get("id", "<unnamed>")
        pattern = entry.get("regex")
        if not pattern:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as e:
            sys.stderr.write(f"[ssproxy] bad extension regex {rule_id!r}: {e}\n")
            continue
        # scrub_secrets._GITLEAKS_COMPILED holds (compiled_pattern, rule_id)
        # tuples used by the text scrubber.
        try:
            scrub_secrets._GITLEAKS_COMPILED.append((compiled, rule_id))
            added += 1
        except Exception as e:
            sys.stderr.write(f"[ssproxy] failed to register extension {rule_id!r}: {e}\n")
    return added


async def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host  # SNI-aware
    if host not in LLM_HOSTS:
        return

    body = flow.request.content
    if not body:
        return
    ctype = flow.request.headers.get("content-type", "")
    if "application/json" not in ctype.lower():
        return
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as e:
        ctx.log.warn(
            f"ssproxy: {host}{flow.request.path}: body not UTF-8 ({e}); pass-through"
        )
        return
    try:
        scrubbed = scrub_text_fixed_length(text)
    except Exception as e:
        ctx.log.error(
            f"ssproxy: scrub failed for {host}{flow.request.path}: {e}; pass-through"
        )
        return
    if scrubbed == text:
        return
    new_body = scrubbed.encode("utf-8")
    # Same-length invariant: any future scrub-pattern that violates this
    # would corrupt the upstream LLM's JSON parser. Fail open (forward
    # the ORIGINAL) and log loudly. The same-length contract is the
    # whole reason yolocage can scrub a body in flight without
    # re-stamping Content-Length or re-parsing JSON.
    if len(new_body) != len(body):
        ctx.log.error(
            f"ssproxy: same-length invariant violated for {host}{flow.request.path} "
            f"(orig={len(body)} scrubbed={len(new_body)}); pass-through"
        )
        return
    flow.request.content = new_body
    # Operator-visible "yes the scrubber is working" line. Count the
    # number of redaction markers in the new body so the operator can
    # see what got caught.
    n = scrubbed.count(scrub_secrets.REDACTED)
    sys.stderr.write(
        f"[ssproxy] redacted {n} secret(s) in {host}{flow.request.path}\n"
    )


def tls_start_server(data) -> None:
    """Mirror the client's ALPN offers upstream.

    Without this, mitmproxy's default may negotiate a different HTTP
    version (h2 vs http/1.1) than the client originally requested. The
    LLM provider sees a different wire fingerprint than a direct
    client — which is exactly the anomaly yolocage wants to avoid
    (the cage should look like an honest claude-code talking direct).
    """
    try:
        client = data.context.client
        server = data.conn
        if not client.alpn_offers:
            return
        mirrored = tuple(client.alpn_offers)
        server.alpn_offers = mirrored
        if data.ssl_conn is not None:
            data.ssl_conn.set_alpn_protos(list(mirrored))
    except Exception as e:
        logging.getLogger(__name__).warning(
            "ssproxy: tls_start_server mirror failed: %r; falling back to default", e
        )


def load(_loader):
    """mitmproxy lifecycle: called once at startup."""
    extras = _load_extensions()
    ctx.log.info(
        f"yolocage ssproxy loaded: {len(LLM_HOSTS)} LLM host(s), "
        f"{len(scrub_secrets._GITLEAKS_COMPILED)} patterns "
        f"({extras} from SSPROXY_EXTENSIONS); marker=\"{scrub_secrets.REDACTED}\""
    )
