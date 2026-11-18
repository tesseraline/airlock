# Threat model

This page is the reference for the security controls in airlock. Each control in the code points to a row in the
table below. If you change a control, update its row in the same commit.

## What we protect

| Asset | Why it matters |
|---|---|
| Tool secrets (API keys, tokens) | a leaked key works outside the system, for anyone |
| The ability to act (send a message, write a file, call a paid API) | an action cannot be taken back |
| Data the tools can read | it can leave through any tool that writes or fetches |
| The policies | whoever can change a policy can allow anything |
| The audit log | without it nobody can say what an agent did |

## Threat sources

1. **Prompt injection.** Text the agent reads, such as a web page or a tool result, contains instructions, and the
   model follows them. Airlock is built mainly for this case.
2. **A compromised agent process.** The code around the model is replaced or exploited and sends whatever requests
   it likes, without the model.
3. **A configuration mistake.** For example, a policy gives an agent more tools than it needs, or an allowlist
   includes a host that accepts uploads.

Out of scope: an attacker with root on the host, a compromised policy author, a malicious maintainer of a tool's
upstream API.

## Trust boundaries

```text
 agent (untrusted)  ──►  gateway (trusted)  ──►  policy (OPA)        decides
                              │
                              ├──►  secret store (Vault)            gateway only
                              └──►  egress proxy (Envoy) ──► OPA ──►  internet, allowlisted hosts only
```

The agent can reach the model and the gateway. Only the gateway can reach the policy engine, the secret store and
the egress proxy. Each of these connections runs on a separate network.

## Threats and controls

| # | Threat | Control | Residual risk |
|---|---|---|---|
| T1 | The agent claims to be another agent with more tools | Mutual TLS: the agent's name comes from its client certificate, issued by the configured CA, never from the request body | whoever holds a stolen key and certificate acts as that agent until the certificate expires |
| T2 | The agent talks to the policy engine directly and rewrites a policy (OPA's REST API accepts writes by default) | The agent has no route to OPA; OPA loads policies read-only from files and denies API writes | — |
| T3 | The agent uses the egress proxy itself, skipping the gateway | The agent has no route to the proxy; only the gateway sits on the proxy's network | — |
| T4 | Injected text makes the model call a dangerous tool or send data out | Per-agent tool lists; argument rules in policy (recipients, hosts, file names); rate limits | data can still leave through an allowed tool to an allowed destination |
| T5 | Policy and tool read an argument differently (`https://good.example@evil.example`, backslashes, IDN) | The gateway parses arguments once; policy and tool get the same normalised value; the egress layer checks the host again | parser bugs in the standard library |
| T6 | A secret leaks to the agent through a tool result or an error message | Secrets held as `Secret` (tesseraline-invariants), which never prints its value; `never_contains(Secret)` promises on the response and error builders, checked in CI; tool output scrubbed of known secret values on every call; errors reduced to a class name | a tool that transforms a secret (base64) defeats exact-match scrubbing |
| T7 | A secret leaks into a log | Three logs, each with its own formatter under a `never_contains(Secret)` promise; logs carry argument names and sizes, and content only where an operator turns it on, scrubbed | — |
| T8 | The policy engine is down and calls go through | Fail closed: no answer, a timeout, or a malformed answer is a deny | calls fail while the policy engine is down |
| T9 | An allowed host resolves to an internal address (cloud metadata, a private service) | Egress refuses private, loopback and link-local destinations | needs the proxy's address checks; added with the cloud examples |
| T10 | An allowed host accepts uploads and becomes an exfiltration channel | Documented: keep allowlists to hosts that only serve; prefer fixed URLs per tool over free URLs | operator choice |
| T11 | Flood: huge requests, endless calls, huge tool output | Body size limit, timeouts, per agent and tool rate limits, output size cap | limits are in memory and reset on restart |
| T12 | A tool has its own bug (path traversal in a file tool) | Policy rules plus a check inside the tool (resolve the path, stay under the root) | a tool bug runs with the gateway's permissions |
| T13 | Gateway compromise | Minimal image, no root, read-only filesystem, one secret path per tool in the store, short-lived store token | all secrets the gateway holds |
| T14 | Tampered release or image | Locked dependencies, scanned image (two scanners), signed releases, actions pinned by commit | — |
| T15 | Nobody can reconstruct what happened | An audit record for every call, written before the tool runs; if the write fails, the call is refused; each record carries the hash of the previous one | whoever controls the log storage can delete the whole log; keep a copy elsewhere |
| T17 | A model behind an API sees everything the agent reads, tool results included | The model route sends traffic only to the configured provider host; the docs say which data suits a remote model | the provider receives the conversation; use a local model for sensitive data |
| T18 | The agent holds a model API key and uses it, or the internet, directly | API keys live in the secret store; the gateway adds them on the model route; the agent has no internet route | — |
| T16 | Tool results reach another system through observability | The observability log stays in a local file and records sizes, not content; content is opt-in per tool and scrubbed | content that an operator turns on is as sensitive as the tool's data |

## Not goals

- Airlock does not check the content of the model's answers. Content filtering is a separate tool.
- Airlock does not isolate the agent process. Run the agent in its own container, with nothing else in it.
- One gateway serves one team. Separate tenants need separate gateways.
