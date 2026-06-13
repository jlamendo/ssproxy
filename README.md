# ssproxy

Egress credential scrubber for LLM API traffic, shipped as a mitmproxy addon library. Intercepts request bodies bound for known LLM hosts (api.anthropic.com, api.openai.com, generativelanguage.googleapis.com, and a handful of others), and replaces credential-shaped strings (API keys, OAuth tokens, JWTs, kubeconfig secrets, cloud provider tokens, etc.) with same-length redaction markers before forwarding upstream.

Built for the case where an agent accidentally reads a `.env` file or a `git config --list` dump into its context, and would otherwise re-send those credentials to the LLM on every subsequent turn. Once a secret is in conversation history, hooks at the agent layer can't reach it. ssproxy catches it on the wire.

## How it works

ssproxy is a mitmproxy addon. It registers a request hook that walks the body bytes through a regex pipeline lifted from gitleaks, plus a small set of cork-curated patterns for labeled-secret shapes (e.g. `password:`, `auth-token:`). Each match is replaced in place with a redaction marker of the same byte length, so Content-Length stays constant and the upstream LLM parses the body identically to the original.

Response bodies pass through untouched. Headers (including bearer tokens that legitimately belong in the request) pass through untouched. The scrubber only touches the request body of requests bound for a known LLM host.

## Install

```bash
pip install ssproxy
```

Or directly into a mitmproxy invocation:

```bash
mitmdump -s $(python -c "import ssproxy, os; print(os.path.join(os.path.dirname(ssproxy.__file__), 'addon.py'))")
```

## Usage as a library

```python
from ssproxy import scrub_text_fixed_length, scrub_text

# Same-length scrub, for byte-stream interception:
clean = scrub_text_fixed_length('export GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
# → 'export GITHUB_TOKEN=[REDACTED BY SSPROXY]*****************'

# Variable-length scrub, for log lines and transcripts:
clean = scrub_text('export GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
# → 'export GITHUB_TOKEN=[REDACTED]'
```

## Custom patterns

Extend the scrubber with your own credential shapes via the `SSPROXY_EXTENSIONS` env var, which points at a JSON file:

```json
[
  { "id": "acme-internal-token", "regex": "\\bACME_[A-Z0-9]{32}\\b" },
  { "id": "acme-deploy-key",     "regex": "\\b(acme_deploy_[a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)" }
]
```

Patterns must follow the byte-stream same-length convention used by the gitleaks rules. Use a capture group for the secret payload, plus a non-capturing trailing anchor (`(?:[\x60'"\s;]|\\[nr]|$)` or similar) so the replacement preserves the byte boundary. Without the trailing anchor, a same-length replacement can overrun a JSON-structural byte and break the upstream request's parsing.

## Hosts intercepted

By default:
- api.anthropic.com
- api.openai.com
- generativelanguage.googleapis.com
- api.deepseek.com
- api.x.ai
- api.cohere.com
- api.mistral.ai

To add hosts, set `SSPROXY_EXTRA_HOSTS` to a comma-separated list, or wrap the addon in your own mitmproxy config.

## Used by

[yolocage](https://github.com/jlamendo/yolocage), an opinionated Docker container for running claude-code and codex in yolo mode safely. Yolocage embeds ssproxy in the container image and routes the agent's egress through it transparently.

## License

MIT. Pattern definitions adapted from [gitleaks](https://github.com/gitleaks/gitleaks), also MIT-licensed.
