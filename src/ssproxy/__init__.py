"""ssproxy — egress credential scrubber for LLM API traffic.

Public surface:
  scrub_text                       — variable-length scrub for log/transcript use
  scrub_text_fixed_length          — byte-stream same-length scrub, suitable for
                                     mitmproxy request-body interception
  fixed_length_redaction           — tier-aware redaction marker generator
  GITLEAKS_PATTERNS                — the lifted pattern list (regex, rule_id)
  REDACTED                         — the variable-length marker string

Anthropic-flavored helpers (for consumers doing more than pure scrubbing):
  find_signed_thinking_spans       — locate Anthropic-signed content-block
                                     byte ranges in an Anthropic /v1/messages
                                     request body
  scrub_text_fixed_length_preserve_signed
                                   — same-length scrub that splices signed
                                     spans back verbatim so upstream's
                                     signature check still passes
  SSEToolUseRewriter               — per-flow SSE state machine for
                                     rewriting Anthropic tool_use blocks
                                     (name-remap, input translation) as
                                     they stream, without buffering the
                                     whole response
  force_identity_encoding          — mitmproxy request-hook helper that
                                     stops the upstream from gzipping
                                     the response (mandatory for
                                     SSEToolUseRewriter callers — see
                                     the module warning for why)
  rewrite_message_json             — JSON (non-streaming) response-body
                                     tool_use rewriter
  ANTHROPIC_HOST                   — "api.anthropic.com"
  ANTHROPIC_MESSAGES_PATH_PREFIX   — "/v1/messages"

Drop the addon into a mitmproxy invocation with:
  mitmdump -s ssproxy/addon.py

The addon honors SSPROXY_EXTENSIONS env (path to a JSON file of custom
patterns, see README for the format) so consumers can ship their own
secret shapes without forking the upstream rule set.
"""

from .scrub_secrets import (
    scrub_text,
    scrub_text_fixed_length,
    fixed_length_redaction,
    REDACTED,
)
from .gitleaks_patterns import GITLEAKS_PATTERNS
from .anthropic_signed import (
    find_signed_thinking_spans,
    scrub_text_fixed_length_preserve_signed,
)
from .tool_use_rewriter import (
    ANTHROPIC_HOST,
    ANTHROPIC_MESSAGES_PATH_PREFIX,
    SSEToolUseRewriter,
    force_identity_encoding,
    rewrite_message_json,
)

__all__ = [
    "scrub_text",
    "scrub_text_fixed_length",
    "fixed_length_redaction",
    "GITLEAKS_PATTERNS",
    "REDACTED",
    "find_signed_thinking_spans",
    "scrub_text_fixed_length_preserve_signed",
    "SSEToolUseRewriter",
    "force_identity_encoding",
    "rewrite_message_json",
    "ANTHROPIC_HOST",
    "ANTHROPIC_MESSAGES_PATH_PREFIX",
]

__version__ = "0.3.0"
