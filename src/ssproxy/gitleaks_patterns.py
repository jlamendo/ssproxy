"""Prefix/format-anchored credential regexes lifted from gitleaks.

Source: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
Upstream license: MIT. Cork's MCP code is MIT — clean lift.

Filter applied: value-format anchored rules only. Rules that match by
context word + entropy (e.g. `(?i)[\\w.-]{0,50}?(?:atlassian)...`) were
dropped — they're too FP-prone in prose, which is most of what flows
through the LLM API. Each rule here keys on a distinctive provider
prefix, infix, or fixed-shape value.

Fixups applied during lift:
  - Go `\\z` (end-of-input) → Python `\\Z`
  - inline `(?i)` (mid-pattern, illegal in Python re) hoisted to a
    single global flag at the start
  - POSIX character classes (`[:alnum:]`, etc.) expanded to ASCII

Replacement contract: when a rule has capture group 1, only that group
is redacted in `scrub_text` (preserving surrounding context characters
that were part of the boundary anchor). When there is no group, the
whole match is replaced.

Maintenance: regen by re-running the lift script when gitleaks releases
new prefix rules. Skip context-word rules unless someone really wants
the FP cost.
"""

from __future__ import annotations

# Each entry: (regex_string, rule_id). The regex string is consumed by
# scrub_secrets._compile_gitleaks() which wraps it with re.compile.
GITLEAKS_PATTERNS: list[tuple[str, str]] = [
    (r"""\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b""", "1password-secret-key"),
    (r"""ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}""", "1password-service-account-token"),
    (r"""(?i)\b(p8e-[a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)""", "adobe-client-secret"),
    (r"""AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}""", "age-secret-key"),
    (r"""\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b""", "airtable-personnal-access-token"),
    (r"""(?i)\b(LTAI[a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)""", "alibaba-access-key-id"),
    (r"""\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)""", "anthropic-admin-api-key"),
    (r"""\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)""", "anthropic-api-key"),
    (r"""\bAKCp[A-Za-z0-9]{69}\b""", "artifactory-api-key"),
    (r"""\bcmVmd[A-Za-z0-9]{59}\b""", "artifactory-reference-token"),
    (r"""(?i)\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})(?:[\x60'"\s;]|\\[nr]|$)""", "authress-service-client-access-key"),
    (r"""\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b""", "aws-access-token"),
    (r"""\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\x60'"\s;]|\\[nr]|$)""", "aws-amazon-bedrock-api-key-long-lived"),
    (r"""bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t""", "aws-amazon-bedrock-api-key-short-lived"),
    (r"""(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])""", "azure-ad-client-secret"),
    (r"""\b(4b1d[A-Za-z0-9]{38})\b""", "clickhouse-cloud-api-secret-key"),
    (r"""(?i)CLOJARS_[a-z0-9]{60}""", "clojars-api-token"),
    (r"""\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\x60'"\s;]|\\[nr]|$)""", "cloudflare-origin-ca-key"),
    (r"""(?i)\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))"|'(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))')(?:\B|\s|\Z)""", "curl-auth-header"),
    (r"""\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w${}@.-]+)))(?:\s|\Z)""", "curl-auth-user"),
    (r"""\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$)""", "databricks-api-token"),
    (r"""\b(doo_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)""", "digitalocean-access-token"),
    (r"""\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)""", "digitalocean-pat"),
    (r"""(?i)\b(dor_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)""", "digitalocean-refresh-token"),
    (r"""(?i)dp\.pt\.[a-z0-9]{43}""", "doppler-api-token"),
    (r"""(?i)duffel_(?:test|live)_[a-z0-9_\-=]{43}""", "duffel-api-token"),
    (r"""(?i)dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}""", "dynatrace-api-token"),
    (r"""(?i)\bEZAK[a-z0-9]{54}\b""", "easypost-api-token"),
    (r"""(?i)\bEZTK[a-z0-9]{54}\b""", "easypost-test-api-token"),
    (r"""(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:[\x60'"\s;]|\\[nr]|$)""", "facebook-access-token"),
    (r"""(?i)\b(EAA[MC][a-z0-9]{100,})(?:[\x60'"\s;]|\\[nr]|$)""", "facebook-page-access-token"),
    (r"""(?i)FLWSECK_TEST-[a-h0-9]{12}""", "flutterwave-encryption-key"),
    (r"""(?i)FLWPUBK_TEST-[a-h0-9]{32}-X""", "flutterwave-public-key"),
    (r"""(?i)FLWSECK_TEST-[a-h0-9]{32}-X""", "flutterwave-secret-key"),
    (r"""\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))(?:[\x60'"\s;]|\\[nr]|$)""", "flyio-access-token"),
    (r"""(?i)fio-u-[a-z0-9\-_=]{64}""", "frameio-api-token"),
    (r"""(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']""", "freemius-secret-key"),
    (r"""\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)""", "gcp-api-key"),
    (r"""(?:ghu|ghs)_[0-9a-zA-Z]{36}""", "github-app-token"),
    (r"""github_pat_\w{82}""", "github-fine-grained-pat"),
    (r"""gho_[0-9a-zA-Z]{36}""", "github-oauth"),
    (r"""ghp_[0-9a-zA-Z]{36}""", "github-pat"),
    (r"""ghr_[0-9a-zA-Z]{36}""", "github-refresh-token"),
    (r"""glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}""", "gitlab-cicd-job-token"),
    (r"""gldt-[0-9a-zA-Z_\-]{20}""", "gitlab-deploy-token"),
    (r"""glffct-[0-9a-zA-Z_\-]{20}""", "gitlab-feature-flag-client-token"),
    (r"""glft-[0-9a-zA-Z_\-]{20}""", "gitlab-feed-token"),
    (r"""glimt-[0-9a-zA-Z_\-]{25}""", "gitlab-incoming-mail-token"),
    (r"""glagent-[0-9a-zA-Z_\-]{50}""", "gitlab-kubernetes-agent-token"),
    (r"""gloas-[0-9a-zA-Z_\-]{64}""", "gitlab-oauth-app-secret"),
    (r"""glpat-[\w-]{20}""", "gitlab-pat"),
    (r"""\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b""", "gitlab-pat-routable"),
    (r"""glptt-[0-9a-f]{40}""", "gitlab-ptt"),
    (r"""GR1348941[\w-]{20}""", "gitlab-rrt"),
    (r"""glrt-[0-9a-zA-Z_\-]{20}""", "gitlab-runner-authentication-token"),
    (r"""\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b""", "gitlab-runner-authentication-token-routable"),
    (r"""glsoat-[0-9a-zA-Z_\-]{20}""", "gitlab-scim-token"),
    (r"""_gitlab_session=[0-9a-z]{32}""", "gitlab-session-cookie"),
    (r"""(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)""", "grafana-api-key"),
    (r"""(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)""", "grafana-cloud-api-token"),
    (r"""(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)""", "grafana-service-account-token"),
    (r"""(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}""", "harness-api-key"),
    (r"""(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}""", "hashicorp-tf-api-token"),
    (r"""\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\x60'"\s;]|\\[nr]|$)""", "heroku-api-key-v2"),
    (r"""\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)""", "huggingface-access-token"),
    (r"""\b(api_org_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)""", "huggingface-organization-api-token"),
    (r"""\b(ico-[a-zA-Z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)""", "infracost-api-token"),
    (r"""(?i)\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:[\x60'"\s;]|\\[nr]|$)""", "intra42-client-secret"),
    # Value-classes here intentionally exclude `\` — JWTs are base64url
    # (A-Z a-z 0-9 - _ . =) so a literal backslash is never part of a
    # legitimate JWT. The upstream gitleaks rule keeps `\\` in the
    # class to tolerate string-literal escapes in source code, but for
    # ssproxy's byte-stream same-length scrubber that lets the capture
    # eat a trailing JSON-escape `\"` backslash, leaving the closing
    # quote unescaped and corrupting the outer JSON. See cork commit
    # log for the original repro (a 233-byte argocd-terraform-token).
    (r"""\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/_-]{17,}\.(?:[a-zA-Z0-9\/_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)""", "jwt"),
    (r"""\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/_+\-\r\n]{40,}={0,2}""", "jwt-base64"),
    (r"""(?i)(?:\bkind:[ \t]*["']?\bsecret\b["']?(?s:.){0,200}?\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))|\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))(?s:.){0,200}?\bkind:[ \t]*["']?\bsecret\b["']?)""", "kubernetes-secret-yaml"),
    (r"""(?i)lin_api_[a-z0-9]{40}""", "linear-api-key"),
    (r"""\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\x60'"\s;]|\\[nr]|$)""", "maxmind-license-key"),
    (r"""https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}""", "microsoft-teams-webhook"),
    (r"""\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\x60'"\s;]|\\[nr]|$)""", "notion-api-token"),
    (r"""(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)""", "npm-access-token"),
    (r"""(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>""", "nuget-config-password"),
    (r"""\b(API-[A-Z0-9]{26})(?:[\x60'"\s;]|\\[nr]|$)""", "octopus-deploy-api-key"),
    (r"""\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)""", "openai-api-key"),
    (r"""\b(sha256~[\w-]{43})(?:[^\w-]|\Z)""", "openshift-user-token"),
    (r"""\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)""", "perplexity-api-key"),
    (r"""(?i)\b(pscale_tkn_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)""", "planetscale-api-token"),
    (r"""\b(pscale_oauth_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)""", "planetscale-oauth-token"),
    (r"""(?i)\b(pscale_pw_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)""", "planetscale-password"),
    (r"""(?i)\b(PMAK-[a-f0-9]{24}\-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)""", "postman-api-token"),
    (r"""\b(pnu_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)""", "prefect-api-token"),
    (r"""(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----""", "private-key"),
    (r"""\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)""", "pulumi-api-token"),
    (r"""pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}""", "pypi-upload-token"),
    (r"""\b(rdme_[a-z0-9]{70})(?:[\x60'"\s;]|\\[nr]|$)""", "readme-api-token"),
    (r"""\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nr]|$)""", "rubygems-api-token"),
    (r"""\b(tk-us-[\w-]{48})(?:[\x60'"\s;]|\\[nr]|$)""", "scalingo-api-token"),
    (r"""(?i)\b(SG\.[a-z0-9=_\-\.]{66})(?:[\x60'"\s;]|\\[nr]|$)""", "sendgrid-api-token"),
    (r"""(?i)\b(xkeysib-[a-f0-9]{64}\-[a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)""", "sendinblue-api-token"),
    (r"""\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\Z)""", "sentry-org-token"),
    (r"""\b(sntryu_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)""", "sentry-user-token"),
    (r"""\b(sm_aat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)""", "settlemint-application-access-token"),
    (r"""\b(sm_pat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)""", "settlemint-personal-access-token"),
    (r"""\b(sm_sat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)""", "settlemint-service-access-token"),
    (r"""\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)""", "shippo-api-token"),
    (r"""shpat_[a-fA-F0-9]{32}""", "shopify-access-token"),
    (r"""shpca_[a-fA-F0-9]{32}""", "shopify-custom-access-token"),
    (r"""shppa_[a-fA-F0-9]{32}""", "shopify-private-app-access-token"),
    (r"""shpss_[a-fA-F0-9]{32}""", "shopify-shared-secret"),
    (r"""(?i)\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)""", "sidekiq-sensitive-url"),
    (r"""(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+""", "slack-app-token"),
    (r"""xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*""", "slack-bot-token"),
    (r"""(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}""", "slack-config-access-token"),
    (r"""(?i)xoxe-\d-[A-Z0-9]{146}""", "slack-config-refresh-token"),
    (r"""xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}""", "slack-legacy-bot-token"),
    (r"""xox[os]-\d+-\d+-\d+-[a-fA-F\d]+""", "slack-legacy-token"),
    (r"""xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}""", "slack-legacy-workspace-token"),
    (r"""xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}""", "slack-user-token"),
    (r"""(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}""", "slack-webhook-url"),
    (r"""\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|$)""", "square-access-token"),
    (r"""\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)""", "stripe-access-token"),
    (r"""SK[0-9a-fA-F]{32}""", "twilio-api-key"),
    (r"""\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)""", "vault-batch-token"),
    (r"""\b((?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24})))(?:[\x60'"\s;]|\\[nr]|$)""", "vault-service-token"),
]
