"""TLS contexts for mutual TLS, and the agent's name from its client certificate."""

from __future__ import annotations

import ssl

AGENT_PREFIX = "spiffe://airlock/agent/"


def server_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """A server context that requires a client certificate signed by `ca` (TLS 1.2 or newer)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.load_verify_locations(ca)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """A client context that presents our certificate and trusts only `ca`."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.load_verify_locations(ca)
    return context


def agent_name(peer: dict[str, object] | None, prefix: str = AGENT_PREFIX) -> str | None:
    """The agent's name from the URI in the certificate's subject alternative names, or None.

    Exactly one URI with the prefix must be present; a certificate with two agent URIs names nobody.

    Examples:
        >>> agent_name({"subjectAltName": (("URI", "spiffe://airlock/agent/researcher"),)})
        'researcher'
        >>> agent_name({"subjectAltName": (("DNS", "agent"),)}) is None
        True
    """
    if not peer:
        return None
    sans = peer.get("subjectAltName", ())
    names = [value[len(prefix) :] for kind, value in sans if kind == "URI" and value.startswith(prefix)]  # type: ignore[attr-defined]
    if len(names) != 1:
        return None
    name = str(names[0])
    return name if name and all(c.isalnum() or c in "-_." for c in name) else None
