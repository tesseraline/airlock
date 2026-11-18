from __future__ import annotations

import json

import pytest

from tesseraline_airlock.egress import EgressRefusedError, normalise
from tesseraline_airlock.records import scrub
from tesseraline_airlock.sinks import HashChainSink, JsonlSink, last_hash, verify_chain
from tesseraline_airlock.tls import agent_name


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "https://good.example@evil.example/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://exa mple.com/",
        "https://example.com\\@evil/",
        "https://bücher.example/",
        "ftp://example.com/",
        "https:///nohost",
        "https://example.com/\r\nX: y",
    ],
)
def test_normalise_refuses(url):
    with pytest.raises(EgressRefusedError):
        normalise(url)


def test_normalise_keeps_path_and_port():
    t = normalise("https://API.Example.com:8443/v1/items?q=1#frag")
    assert (t.host, t.port, t.path, t.authority) == ("api.example.com", 8443, "/v1/items?q=1", "api.example.com:8443")


def test_agent_name_needs_exactly_one_agent_uri():
    one = {"subjectAltName": (("URI", "spiffe://airlock/agent/a1"),)}
    two = {"subjectAltName": (("URI", "spiffe://airlock/agent/a1"), ("URI", "spiffe://airlock/agent/a2"))}
    odd = {"subjectAltName": (("URI", "spiffe://airlock/agent/a b"),)}
    assert agent_name(one) == "a1"
    assert agent_name(two) is None
    assert agent_name(odd) is None
    assert agent_name(None) is None


def test_scrub_counts_and_ignores_tiny_values():
    assert scrub("aa tok-123 tok-123", ["tok-123", "aa"]) == ("aa [redacted] [redacted]", 2)


def test_hash_chain_detects_a_changed_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = HashChainSink(JsonlSink(path), last_hash(path))
    for n in range(3):
        sink.write({"n": n})
    assert verify_chain(path) == (True, 3)
    HashChainSink(JsonlSink(path), last_hash(path)).write({"n": 3})  # continues after a restart
    assert verify_chain(path) == (True, 4)
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["n"] = 99
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")
    assert verify_chain(path) == (False, 2)


def test_audit_file_with_a_damaged_line_is_reported(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = HashChainSink(JsonlSink(path), last_hash(path))
    sink.write({"n": 1})
    with path.open("a") as handle:
        handle.write('{"n": 2, "pre')  # a half-written line
    assert verify_chain(path) == (False, 2)
    with pytest.raises(ValueError, match="airlock audit verify"):
        last_hash(path)


def test_parallel_calls_see_each_other_in_the_rate_count():
    from tesseraline_airlock.limits import CallCounter

    counter = CallCounter()
    counts = [counter.reserve("a", "fetch")[0] for _ in range(5)]
    assert counts == [0, 1, 2, 3, 4]
    _, token = counter.reserve("a", "x-invented")
    counter.release("a", "x-invented", token)
    assert ("a", "x-invented") not in counter._calls  # refused names leave nothing behind


def test_policy_answer_of_the_wrong_shape_is_a_refusal(monkeypatch):
    import io

    from tesseraline_airlock.policy import OpaPolicy

    policy = OpaPolicy("http://opa.invalid", None)

    class Answer(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    for raw in (b"[1, 2]", b'{"result": [true]}', b'{"result": {"allow": "yes"}}', b"\xff"):
        monkeypatch.setattr(policy._opener, "open", lambda *a, raw=raw, **k: Answer(raw))
        assert policy.decide({"tool": "t"}).allow is False


def test_names_that_point_inside_are_refused():
    from tesseraline_airlock.egress import Egress, normalise
    from tesseraline_airlock.tls import client_context  # noqa: F401

    def fake(answers):
        return lambda host, port, **k: [(2, 1, 6, "", (a, port)) for a in answers[host]]

    answers = {
        "metadata.example": ["169.254.169.254"],
        "inside.example": ["10.0.0.5"],
        "mixed.example": ["93.184.215.14", "127.0.0.1"],
        "v6.example": ["fd00::1"],
        "public.example": ["93.184.215.14"],
    }
    egress = Egress(None, None, resolve=fake(answers), private_hosts=frozenset({"inside.example"}))
    for host in ("metadata.example", "mixed.example", "v6.example"):
        with pytest.raises(EgressRefusedError, match="non-public"):
            egress.open("GET", normalise(f"https://{host}/"), {})
    from tesseraline_airlock.egress import private_address

    assert private_address("public.example", 443, fake(answers)) == ""
    assert private_address("inside.example", 443, fake(answers)) == "10.0.0.5"  # listed hosts skip the check in open()


def test_token_meter_sums_the_last_hour():
    from tesseraline_airlock.limits import TokenMeter

    meter = TokenMeter(window=100)
    meter.add("a", 30, now=0)
    meter.add("a", 20, now=50)
    assert meter.used("a", now=60) == 50
    assert meter.used("a", now=120) == 20
    assert meter.used("b") == 0
