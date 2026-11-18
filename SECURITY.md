# Security policy

## Supported versions

Only the latest release on PyPI receives security fixes.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
<https://github.com/tesseraline/airlock>. Do not open a public issue for a vulnerability.

Include the steps that reproduce the problem and the version you used. We aim to confirm receipt within
five working days and to agree a disclosure date with you once a fix is ready.

## What counts

- A call that runs without an allow from the policy, or without its audit record.
- An agent acting under another agent's name, or reaching the policy engine, the secret store or the egress proxy.
- A secret from the store in a response to the agent or in any of the three logs.
- A request leaving through the egress proxy to a host the egress policy does not list.
- Anything in the published package, the image build or the release process that could be tampered with.

The limits listed in the README under "Known limits" are not vulnerabilities.

## Releases

Releases are published by GitHub Actions through PyPI Trusted Publishing. Each file on PyPI carries a
provenance attestation tied to this repository's `publish.yml`, and each GitHub release carries the files with a
Sigstore signature.
