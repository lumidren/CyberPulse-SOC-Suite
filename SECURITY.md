# Security Policy

CyberPulse SOC Suite is a **defensive SOC training and simulation platform**. All
"attacks" are synthetic telemetry generators; no offensive tooling is included.
Still, the REST server and web console are real software, and this policy covers them.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 2.5.x   | ✅        |
| < 2.5   | ❌        |

## Hardening Baseline (what the server enforces)

- **API authentication** on every `/api/*` endpoint via `X-API-Key` or
  `Authorization: Bearer`, compared in constant time (`hmac.compare_digest`).
- **Production key enforcement**: with `CYBERPULSE_ENV=production`, the server
  refuses to start unless `CYBERPULSE_API_KEY` is explicitly set.
- **Rate limiting**: per-client sliding window (`RATE_LIMIT_PER_MINUTE`, default
  240/min) plus a stricter failed-authentication throttle
  (`AUTH_FAILURE_LIMIT_PER_MINUTE`, default 10/min → `429`).
- **Request body cap**: `MAX_BODY_BYTES` (default 1 MiB) → `413`.
- **Strict JSON parsing**: malformed POST bodies are rejected with `400`.
- **SSRF guard**: analyst-supplied webhook URLs must be `http(s)` and may not
  target loopback/private/link-local/reserved addresses unless
  `ALLOW_INTERNAL_WEBHOOKS=true` is set.
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY`, `Referrer-Policy: no-referrer` on every response.
- **Origin-restricted CORS** (`CORS_ALLOWED_ORIGIN`).
- **Audit logging** of state-changing actions (simulations, rollbacks, policy
  changes) with client IP attribution.
- **Container**: runs as a non-root user with a `/healthz` healthcheck.

## Deployment Guidance

1. Never expose the lab server directly to the internet; front it with a reverse
   proxy that terminates TLS.
2. Set `CYBERPULSE_ENV=production` and a strong `CYBERPULSE_API_KEY`
   (`python -c "import secrets; print(secrets.token_urlsafe(32))"`).
3. Keep `ALLOW_INTERNAL_WEBHOOKS=false` unless your notification target is on a
   trusted internal network.
4. Rotate the API key if it is ever committed, logged, or shared.

## Reporting a Vulnerability

Open a GitHub issue with the `security` label, or report privately via GitHub
Security Advisories on this repository. Please include reproduction steps and
affected versions. You can expect an initial response within 7 days.
