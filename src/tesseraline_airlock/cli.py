"""`airlock serve` runs the gateway; `airlock obs ...` reads the observability log; `airlock audit verify`."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ENV_HELP = """environment:
  AIRLOCK_CERT, AIRLOCK_KEY   the gateway's certificate and key (server and client)
  AIRLOCK_CA                  the CA that signs agents and internal services
  AIRLOCK_OPA_URL             e.g. https://opa-tools:8181
  AIRLOCK_VAULT_URL           e.g. https://vault:8200
  AIRLOCK_EGRESS_URL          e.g. https://egress:10000
  AIRLOCK_CONFIG              JSON with host credentials and model routes (optional)
  AIRLOCK_LOG_DIR             where developer.jsonl, audit.jsonl and observability.jsonl go
  AIRLOCK_PORT                default 8443
  AIRLOCK_MAX_CONNECTIONS     connections handled at once, default 64
"""


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        sys.exit(f"airlock: {name} is not set")
    return value


def _hosts(value: object) -> frozenset[str]:
    """Host names from the configuration's `private_hosts` list."""
    return frozenset(str(h) for h in value) if isinstance(value, list) else frozenset()


def _last(audit_file: Path) -> str:
    """The audit chain's last hash; a damaged audit file stops the start (fail closed)."""
    from tesseraline_airlock.sinks import last_hash

    try:
        return last_hash(audit_file)
    except ValueError as error:
        sys.exit(f"airlock: {error}")


def serve(tools_modules: list[str]) -> None:
    """Build the gateway from the environment and run it."""
    from tesseraline_airlock import tools as tool_registry
    from tesseraline_airlock.egress import Egress
    from tesseraline_airlock.fetch import HostCredential, make_fetch
    from tesseraline_airlock.gateway import Gateway, Logs
    from tesseraline_airlock.model import load_routes
    from tesseraline_airlock.policy import OpaPolicy
    from tesseraline_airlock.secrets import VaultCertStore
    from tesseraline_airlock.server import CertFiles
    from tesseraline_airlock.server import serve as run
    from tesseraline_airlock.sinks import HashChainSink, JsonlSink
    from tesseraline_airlock.tls import client_context, server_context

    cert, key, ca = _env("AIRLOCK_CERT"), _env("AIRLOCK_KEY"), _env("AIRLOCK_CA")
    config_path = os.environ.get("AIRLOCK_CONFIG")
    config: dict[str, object] = json.loads(Path(config_path).read_text()) if config_path else {}
    logs_dir = Path(_env("AIRLOCK_LOG_DIR", "/var/log/airlock"))
    audit_file = logs_dir / "audit.jsonl"
    logs = Logs(
        developer=JsonlSink(logs_dir / "developer.jsonl"),
        audit=HashChainSink(JsonlSink(audit_file, sync=True), _last(audit_file)),
        observability=JsonlSink(logs_dir / "observability.jsonl"),
    )
    contexts = [CertFiles(client_context(cert, key, ca), cert, key, ca) for _ in range(3)]
    raw_credentials = config.get("credentials", {})
    credentials = (
        {host: HostCredential(**spec) for host, spec in raw_credentials.items()}
        if isinstance(raw_credentials, dict)
        else {}
    )
    tools = [make_fetch(credentials)]
    for module in tools_modules:
        tools.extend(tool_registry.load(module))
    gateway = Gateway(
        policy=OpaPolicy(_env("AIRLOCK_OPA_URL"), contexts[0].context),
        store=VaultCertStore(_env("AIRLOCK_VAULT_URL"), contexts[1].context),
        egress=Egress(
            _env("AIRLOCK_EGRESS_URL"),
            contexts[2].context,
            private_hosts=_hosts(config.get("private_hosts")),
        ),
        tools=tools,
        logs=logs,
    )
    run(
        gateway,
        load_routes(config),
        CertFiles(server_context(cert, key, ca), cert, key, ca),
        int(_env("AIRLOCK_PORT", "8443")),
        contexts,
    )


def _records(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        sys.exit(f"airlock: no log at {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def obs(command: str, arg: str | None, log_dir: Path) -> None:
    """Summaries of the observability log."""
    path = log_dir / "observability.jsonl"
    if command == "tail":
        with path.open(encoding="utf-8") as handle:
            handle.seek(0, os.SEEK_END)
            while True:
                line = handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                r = json.loads(line)
                print(f"{r['ts']}  {r['agent']:<14} {r['tool']:<18} {r['decision']:<5} {r['ms']:>6} ms  {r['reason']}")
    rows = _records(path)
    if command == "summary":
        calls, denied, slow = Counter[str](), Counter[str](), defaultdict[str, list[int]](list)
        reasons = Counter[str]()
        for r in rows:
            tool = str(r["tool"])
            calls[tool] += 1
            slow[tool].append(int(r.get("ms", 0)))  # type: ignore[call-overload]
            if r["decision"] == "deny":
                denied[tool] += 1
                reasons[str(r["reason"])] += 1
        print(f"{'tool':<22}{'calls':>7}{'denied':>8}{'max ms':>9}")
        for tool, n in calls.most_common():
            print(f"{tool:<22}{n:>7}{denied[tool]:>8}{max(slow[tool]):>9}")
        if reasons:
            print("\nmost common refusal reasons:")
            for reason, n in reasons.most_common(5):
                print(f"  {n:>4}  {reason}")
    elif command == "session":
        for r in (r for r in rows if r.get("session") == arg):
            print(f"{r['step']:>3}  {r['ts']}  {r['tool']:<18} {r['decision']:<5} {r['ms']:>6} ms  {r['reason']}")


def main(argv: list[str] | None = None) -> int:
    """Entry point of the `airlock` command."""
    parser = argparse.ArgumentParser(prog="airlock", epilog=ENV_HELP, formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    serve_p = sub.add_parser("serve", help="run the gateway")
    serve_p.add_argument("--tools", action="append", default=[], help="a module with @tool functions (repeatable)")
    obs_p = sub.add_parser("obs", help="read the observability log")
    obs_p.add_argument("what", choices=["summary", "session", "tail"])
    obs_p.add_argument("session", nargs="?")
    obs_p.add_argument("--log-dir", default=os.environ.get("AIRLOCK_LOG_DIR", "/var/log/airlock"))
    audit_p = sub.add_parser("audit", help="check the audit log's hash chain")
    audit_p.add_argument("what", choices=["verify"])
    audit_p.add_argument("--log-dir", default=os.environ.get("AIRLOCK_LOG_DIR", "/var/log/airlock"))
    args = parser.parse_args(argv)
    if args.command == "serve":
        serve(args.tools)
    elif args.command == "obs":
        obs(args.what, args.session, Path(args.log_dir))
    else:
        from tesseraline_airlock.sinks import verify_chain

        intact, line = verify_chain(Path(args.log_dir) / "audit.jsonl")
        print(f"audit chain intact, {line} records" if intact else f"audit chain BROKEN at line {line}")
        return 0 if intact else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
