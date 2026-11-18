# Design (v0.0.1)

## Overview

The agent sends each tool call to the gateway and never runs a tool itself. The gateway identifies the agent from
its client certificate and asks the policy engine whether the call is allowed. If it is, the gateway runs the tool with secrets
that only the gateway holds, removes those secrets from the result and returns it. When a tool connects to the
internet, the connection goes through the egress proxy, which checks the host against a second policy. The agent
holds no secrets and can reach only the model and the gateway.

## Components

| Part | What it is | Ships as |
|---|---|---|
| gateway | Python package: HTTPS endpoint with mutual TLS, tool registry, model route, policy client, rate limits, secret store interface, scrubbing, three log sinks | `tesseraline-airlock` on PyPI; Dockerfile in the repo |
| policies | `tools.rego` (which agent, which tool, which arguments, limits) and `egress.rego` (which hosts), with tests | files in `policies/` |
| example | agent, gateway, two OPA instances, Envoy, Vault in dev mode, a small `demo-api`, an optional local model, separate networks; a script that creates a local CA and the certificates | `examples/terraform/docker/` |

The gateway's only runtime dependency is `tesseraline-invariants` (pinned `>=0.0.3,<0.1`), which itself needs
nothing outside the standard library. Every value read from the secret store is held as a `Secret`. Five functions
build text that leaves the gateway, and each carries `@invariant(never_contains(Secret))`. They build the response
to the agent, the error message and the entries of the three logs. `invariants check` runs in CI against a
committed `invariants.lock`. This check runs on generated inputs at test time. The runtime scrubbing of known secret
values stays in place for every call. When airlock needs a feature that invariants lacks, the feature is added to
invariants first and released there.

## Gateway API

```text
POST /v1/call            {"tool": "fetch", "args": {"url": "https://example.com/"}}
                     ->  {"request_id": "...", "allow": true, "reason": "allowed", "output": "..."}
POST /v1/model/<route>   the model provider's own request, passed through unchanged
GET  /healthz        ->  200 when the policy engine answers
```

- Identity: every connection uses mutual TLS. The agent's name is the URI in its client certificate's subject
  alternative name, for example `spiffe://airlock/agent/researcher`. A connection without a certificate from the
  configured CA is closed before any request is read. The request body carries no agent name.
- Every refusal has the same shape with `"allow": false` and the policy's reason. A policy refusal returns HTTP 200;
  a malformed request returns 400 and a body over the limit returns 413.

## Certificates

Every internal connection uses mutual TLS: agent to gateway, gateway to OPA, gateway to Vault and gateway to the
egress proxy. The README carries a table of each file, its path, the environment variable that points to it, who
issues it and how long it is valid. Certificates are short-lived. The gateway loads new ones on restart or on
SIGHUP. The example creates a local CA and the certificates with a script and keeps the private keys in a folder
that git ignores. It does not use Terraform's `tls` provider, because that provider stores private keys in the
Terraform state.

## Tools

Tools run inside the gateway container. The agent only asks for a call, so the keys and the network access stay
with the gateway. A user writes tools as Python functions marked `@tool`, points the gateway at the module
(`airlock serve --tools mypackage.tools`) and adds rules for the new tools to the policy data.

Airlock ships one tool, `fetch`, which downloads a page from an allowed host through the egress proxy. For hosts
that need a credential, the gateway adds it to the request from the secret store. The example shows this with
`demo-api`, a small service in the stack that requires a token the agent never sees.

## Model route

The agent can use a local model or a model behind a provider's API.

- A local model (llama.cpp, vLLM, Ollama) runs on the internal network. The agent calls it directly and needs no
  key and no internet access.
- A model behind an API goes through the gateway. The agent sends its request to `/v1/model/<route>`; the gateway
  adds the provider's key from the secret store and forwards the request through the egress proxy to that
  provider's host only. The agent holds no key and has no internet access.

The gateway passes requests and responses through unchanged, streaming included. It does not translate between
providers' protocols. The agent speaks each provider's own API. Because
model traffic passes the gateway, the observability log records the model, token counts and model latency as the
gateway measures them. These fields are read from the provider's usage data.

## Python API (what a user writes)

```python
from tesseraline_airlock import Gateway, OpaPolicy, VaultCertStore, tool

@tool(secret="inventory-api")                # the gateway reads this secret from the store, the tool gets it
def stock_level(args, secret):
    ...

gateway = Gateway(policy=OpaPolicy("https://opa-tools:8181"), store=VaultCertStore(...), tools=[stock_level])
gateway.serve(port=8443)
```

The policy input is fixed and documented: `agent`, `tool`, `args` (normalised), `calls_last_hour` for this agent and
tool. The gateway keeps the call counts and the policy compares them with the limits.

## Logs

The gateway writes three separate logs, compared in the table below.

| | Developer | Audit | Observability |
|---|---|---|---|
| Purpose | debugging the gateway | a record of who did what and why it was allowed | which tools agents call, how long the calls take and where the policy refuses them |
| Content | errors, timings, code paths; never argument values | one record per call: request id, time, agent, tool, decision, reason, policy file hash, argument names with SHA-256 of their values, output size | one record per call, described below |
| If the write fails | the gateway carries on | **the call is refused** | the gateway carries on |
| Protection | log level (WARN in production) | append only; each record carries the hash of the previous one, so a removed or altered record shows; stored apart, with narrow access | off by default; a local file |

Each log is a `Sink`. The default sink writes JSON Lines to its own file or stream; a collector can forward them.

### Observability records

```json
{"ts": "2026-03-02T10:40:12.381Z", "ms": 412, "request_id": "r-7f3a",
 "session": "s-91c2", "step": 3, "agent": "researcher",
 "model": {"reported": "example-model"},
 "tool": "fetch_page", "decision": "allow", "reason": "allowed",
 "args": {"url": {"bytes": 31}}, "output": {"bytes": 2000, "truncated": true, "scrubbed": 0},
 "error": null}
```

| Field | Source | Meaning |
|---|---|---|
| `ts`, `ms` | gateway | when the call started and how long it took |
| `request_id` | gateway | the key shared with the audit record |
| `session` | agent, header `X-Airlock-Session` | groups the calls of one task |
| `step` | gateway | the call's position within its session |
| `agent` | client certificate | who made the call |
| `model` | gateway (model route) or agent (`X-Airlock-Model`, stored as `reported`) | the model; measured when the call goes through the model route |
| `tool`, `decision`, `reason` | gateway and policy | the call and its outcome |
| `args`, `output` | gateway | names and sizes; `scrubbed` counts secret values removed from the output |
| `error` | gateway | the exception class, if any |

Fields that come from the agent are stored under a `reported` key or named as such, because the agent is not
trusted. The agent's identity always comes from its client certificate. Argument and output content is off by default. An
operator can turn it on per tool; the content is scrubbed and cut to a size limit before it is written.

A small command line reader works on the same file:

```console
$ airlock obs summary          # calls and refusals per tool, slowest calls, most common refusal reasons
$ airlock obs session s-91c2   # one session step by step: tool, decision, time
$ airlock obs tail             # new records as they arrive, formatted
```

Calls to a local model do not pass the gateway, so for them the model name is the one the agent reports.

## Repository layout

```text
src/tesseraline_airlock/   gateway package
policies/                  tools.rego, egress.rego, tests
examples/terraform/docker/ the local stack
docker/Dockerfile          gateway image (pinned base by digest, non-root, read-only)
docs/                      this page, threat model, getting started, policies, operations
tests/                     unit tests; one end-to-end test against the stack (manual, not in CI)
```

## Checks (CI)

| Step | Tool | Blocks |
|---|---|---|
| lint, types, tests | ruff, mypy, pytest | yes |
| dependencies | pip-audit | known vulnerabilities |
| policies | `opa test`, `opa fmt --diff` | yes |
| Terraform | `terraform fmt -check`, `validate`; `trivy config` | HIGH and CRITICAL |
| image | Syft (SBOM) and Grype; Trivy as a second scanner | fixable HIGH and CRITICAL in either |
| promises | `invariants check` against `invariants.lock` | a broken or removed promise |
| supply chain | actions pinned by commit, Dependabot, Scorecard | rule |

CI installs Trivy from a pinned release binary and checks its checksum and signature before running it. The Trivy
job has read-only permissions and no access to secrets. An accepted finding goes into an exceptions file with a
reason and a date.

## Milestones

| Version | Scope |
|---|---|
| 0.0.1 | gateway, policies, local Terraform example, docs, CI |
| 0.1 | official image on GHCR, signed, with SBOM |
| 0.2 | AWS example: container service, managed secrets, workload role, egress through the proxy, metadata address blocked |
| 0.3 | Azure example: container apps, key vault, managed identity |

## Decisions

- A human approval hook for chosen tools (the policy returns "ask" and a person confirms) comes after 0.0.1.
- Mutual TLS for agent identity, from 0.0.1 (decided). The certificate table is part of the README.
