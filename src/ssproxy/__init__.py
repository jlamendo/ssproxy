"""ssproxy — egress credential scrubber for LLM API traffic.

Public surface:
  scrub_text                       — variable-length scrub for log/transcript use
  scrub_text_fixed_length          — byte-stream same-length scrub, suitable for
                                     mitmproxy request-body interception
  fixed_length_redaction           — tier-aware redaction marker generator
  GITLEAKS_PATTERNS                — the lifted pattern list (regex, rule_id)
  REDACTED                         — the variable-length marker string

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

__all__ = [
    "scrub_text",
    "scrub_text_fixed_length",
    "fixed_length_redaction",
    "GITLEAKS_PATTERNS",
    "REDACTED",
]

__version__ = "0.1.0"
