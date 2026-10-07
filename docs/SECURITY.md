# Security & Authorized Use

## Authorized use only

RedVector is a security-testing platform for **authorized** engagements. Use it only against systems you own or have **explicit, written permission** to test. Unauthorized scanning, exploitation, or access is illegal in most jurisdictions. You are solely responsible for complying with all applicable laws, regulations, and contracts.

## Scope discipline

- Define and respect an engagement scope; do not test out-of-scope hosts.
- Prefer non-destructive techniques; understand the impact of any action before running it.
- Keep evidence and logs according to your engagement's rules of engagement.

## How RedVector executes tools

RedVector constructs command lines for external security binaries and runs them through a shared executor. It does **not** bundle or install those tools. A missing binary yields a failure result rather than a crash.

## Credentials & secrets

- AI provider API keys are stored via the OS keyring when available, otherwise read-only from environment variables. RedVector never writes plaintext secrets and never logs or returns secret values.
- The default backend API token (`redvector-dev-token`) is a development convenience. **Set `REDVECTOR_API_TOKEN` to a strong value** before exposing the backend beyond localhost.
- The backend binds to `127.0.0.1` by default. Do not expose it publicly without authentication, TLS, and network controls appropriate to your environment.

## Reporting a vulnerability

If you discover a security issue in RedVector itself, report it privately to the maintainer rather than filing a public issue.

## No warranty

RedVector is provided "as is" under the MIT License, without warranty of any kind. See [../LICENSE](../LICENSE).
