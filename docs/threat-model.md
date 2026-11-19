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
| T2 | The agent talks to the policy engine directly and rewrites a policy (OPA's REST API accepts writes by default) | The agent has no route to OPA; OPA loads policies read-only from files and denies API writes | none |
| T3 | The agent uses the egress proxy itself, skipping the gateway | The agent has no route to the proxy; only the gateway sits on the proxy's network, and the proxy accepts only the gateway's client certificate | the proxy and its policy engine talk without TLS, on a network only they share |
| T4 | Injected text makes the model call a dangerous tool or send data out | Per-agent tool lists; argument rules in policy (recipients, hosts, file names); rate limits | data can still leave through an allowed tool to an allowed destination |
| T5 | Policy and tool read an argument differently (`https://good.example@evil.example`, backslashes, IDN) | The gateway parses arguments once; policy and tool get the same normalised value; the egress layer checks the host again. On the model route the body must parse and the forwarded body is the one the policy judged; route paths with `..`, `.` or `//` are refused, and the proxy normalises paths | parser bugs in the standard library |
| T6 | A secret leaks to the agent through a tool result or an error message | Secret values in fields marked `Secret[str]` (tesseraline-invariants), in records whose printed form leaves them out; `never_contains(Secret)` promises on the builders of the response, the error message and the log entries, checked in CI; tool output scrubbed of known secret values on every call; errors reduced to a class name | a tool that transforms a secret (base64) defeats exact-match scrubbing |
| T7 | A secret leaks into a log | Three logs, each with its own formatter under a `never_contains(Secret)` promise; logs carry argument names, sizes and hashes, never argument or output content | none |
| T8 | The policy engine is down and calls go through | Fail closed: no answer, a timeout, or a malformed answer is a deny | calls fail while the policy engine is down |
| T9 | An allowed host resolves to an internal address (cloud metadata, a private service) | Before a request leaves, the gateway resolves the name and refuses private, loopback, link-local and reserved addresses, except for hosts listed as your own (`private_hosts`) | the egress proxy resolves the name again, so a name that changes its address between the two lookups is not caught |
| T10 | An allowed host accepts uploads and becomes an exfiltration channel | Documented: keep allowlists to hosts that only serve; prefer fixed URLs per tool over free URLs | operator choice |
| T11 | Flood: huge requests, endless calls, huge tool output | Body size limit; a request without a valid Content-Length is refused; a cap on connections handled at once; timeouts; rate limits per agent and tool, counted before the policy is asked so parallel calls see each other; a token budget per agent and hour on model routes; caps on tool output and model answers; container memory, CPU and file limits | limits are in memory and reset on restart |
| T12 | A tool has its own bug (path traversal in a file tool) | Policy rules plus a check inside the tool (resolve the path, stay under the root) | a tool bug runs with the gateway's permissions |
| T13 | Gateway compromise | Minimal image, no root, read-only filesystem, one secret path per tool in the store, short-lived store token | all secrets the gateway holds |
| T14 | Tampered release or image | Locked dependencies, scanned image (two scanners), signed releases, actions pinned by commit | none |
| T15 | Nobody can reconstruct what happened | An audit record for every call, written before the tool runs; if the write fails, the call is refused; each record carries the hash of the previous one | whoever controls the log storage can delete the whole log; keep a copy elsewhere |
| T17 | A model behind an API sees everything the agent reads, tool results included | The model route sends traffic only to the configured provider host; the docs say which data suits a remote model | the provider receives the conversation; use a local model for sensitive data |
| T18 | The agent holds a model API key and uses it, or the internet, directly | API keys live in the secret store; the gateway adds them on the model route; the agent has no internet route | none |
| T16 | Tool results reach another system through observability | The observability log stays in a local file and records sizes, not content | a `Sink` an operator writes decides where records go |

## MCP (0.1, part A)

Threats added by the MCP bridge and endpoint, sorted by the layers of the MAESTRO threat-modelling framework (Cloud
Security Alliance) and mapped to the OWASP Top 10 for LLM applications (2025).

| # | MAESTRO layer | OWASP LLM | Threat | Control | Residual risk |
|---|---|---|---|---|---|
| M1 | 7 Agent ecosystem | LLM06 | The agent lists or calls tools it was not given | `tools/list` filtered by the policy; every `tools/call` decided by the policy | none |
| M2 | 3 Agent frameworks | LLM01 | A tool description carries instructions to the model (tool poisoning) | Names, descriptions and schemas only from the gateway's code. At start every string is folded to its plain Unicode form and checked: no control characters, no markup (angle brackets, backticks, Markdown headings), limits on length and lines; names use letters, digits, `_`, `-` and `.` only | a description written badly by the operator; part B adds pinned descriptions for other servers |
| M3 | 4 Deployment and infrastructure | LLM06 | The machine running the bridge is taken over and its certificate used | Short-lived certificates; the bridge holds nothing else; the policy limits what the agent can do | whoever holds the certificate acts as the agent until it expires |
| M4 | 7 Agent ecosystem | none | Another local process talks to the bridge | The bridge speaks only on the stdio of the process that started it and opens no port | a process with the same user's rights can start its own bridge with the same certificate |
| M5 | 3 Agent frameworks | LLM05 | Malformed or oversized JSON-RPC, batches, unknown methods | Strict parsing, the same body limits on both sides of the bridge, batches refused, ids only strings or integers, unknown methods answered with an error; the bridge passes on only JSON-RPC answers and survives undecodable or oversized lines | none |
| M6 | 6 Security and compliance | LLM10 | MCP used to get around limits | `tools/call` uses the same rate limits and token budget as `/v1/call` | none |
| M7 | 5 Evaluation and observability | LLM02 | MCP calls missing from the logs, or secrets in them | `tools/call` audited before it runs, an unknown tool included; `tools/list` in the observability log; the client's reported name kept apart from the model; the same record builders and promises | none |
| M8 | 7 Agent ecosystem | LLM01 | A tool result carries instructions (indirect prompt injection) | As T4: the policy limits what any later call can do | as T4 |
| M9 | 6 Security and compliance | none | A version mismatch makes the gateway fall back to weaker behaviour | The gateway serves one revision, read from each request's `_meta` (a header must agree), and refuses others with the list it supports; legacy clients are handled only in the bridge | none |

## Not goals

- Airlock does not check the content of the model's answers. Content filtering is a separate tool.
- Airlock does not isolate the agent process. Run the agent in its own container, with nothing else in it.
- One gateway serves one team. Separate tenants need separate gateways.
