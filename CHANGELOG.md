# Changelog

All notable changes to tesseraline-airlock. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Before 1.0 a minor version may change the public API.

## [Unreleased]

## [0.0.1] - 2026-11-18

### Added
- The gateway: tool calls over HTTPS with mutual TLS, the agent's name from its client certificate.
- The tools policy (OPA) asked before every call; no answer is a refusal.
- The `fetch` tool, with credentials the gateway adds per host from the secret store.
- The model route: requests to a model API pass through the gateway, which adds the key; streaming included.
- Secrets from HashiCorp Vault through certificate login, removed from every result before it reaches the agent.
- Three logs (developer, audit, observability) behind a `Sink` interface; the audit log is hash-chained and a call
  is refused when its audit record cannot be written.
- `airlock obs summary | session | tail` and `airlock audit verify`.
- Egress policy for Envoy; the example stack in Terraform with Docker.
- Promises (tesseraline-invariants) that the text leaving the gateway contains no secret.
- A token budget per agent and hour on model routes, decided by the policy.
- Destinations that resolve to private, loopback, link-local or reserved addresses are refused.
- An optional `Redactor` interface for personal data in tool output and model answers.
- Security events under one name (`security`) in the developer log, for alerting.
- A limit on connections handled at once (`AIRLOCK_MAX_CONNECTIONS`); container limits in the example.

[Unreleased]: https://github.com/tesseraline/airlock/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/tesseraline/airlock/releases/tag/v0.0.1
