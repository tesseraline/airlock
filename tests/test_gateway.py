from __future__ import annotations

import json

from conftest import FakePolicy
from tesseraline_airlock.gateway import Gateway, Logs
from tesseraline_airlock.secrets import StaticStore
from tesseraline_airlock.sinks import MemorySink
from tesseraline_airlock.tools import tool


@tool()
def leaky(args, context):
    """Returns its secret, as a careless tool might."""
    return f"used key {context.secret('api')} for {args.get('q')}"


@tool()
def broken(args, context):
    raise RuntimeError("boom with details that must not reach the agent")


class FailingSink:
    def write(self, record):
        raise OSError("disk full")


def make(allowed, audit=None, up=True):
    logs = Logs(MemorySink(), audit or MemorySink(), MemorySink())
    gateway = Gateway(
        policy=FakePolicy(allowed, up),
        store=StaticStore({"api": "sk-very-secret-1"}),
        egress=None,
        tools=[leaky, broken],
        logs=logs,
    )
    return gateway, logs


def test_allowed_call_scrubs_the_secret_and_logs_three_times():
    gateway, logs = make({"leaky"})
    status, body = gateway.call_tool(
        "researcher", {"tool": "leaky", "args": {"q": "stock"}}, session="s-1", reported_model="m-1"
    )
    answer = json.loads(body)
    assert status == 200 and answer["allow"] is True
    assert "sk-very-secret-1" not in body and "[redacted]" in answer["output"]
    audit = logs.audit.records[0]
    assert audit["decision"] == "allow" and audit["agent"] == "researcher" and "q" in audit["args"]
    assert "stock" not in json.dumps(audit)  # argument values only as hashes
    obs = logs.observability.records[0]
    assert obs["output"]["scrubbed"] == 1 and obs["session"] == "s-1" and obs["step"] == 1
    assert obs["model"] == {"reported": "m-1"}
    assert all("sk-very-secret-1" not in json.dumps(r) for r in logs.developer.records)


def test_refused_call_does_not_run():
    gateway, logs = make(set())
    _, body = gateway.call_tool("researcher", {"tool": "leaky", "args": {}})
    assert json.loads(body)["allow"] is False
    assert logs.audit.records[0]["decision"] == "deny"
    assert gateway.counter.count("researcher", "leaky") == 0


def test_policy_down_is_a_refusal():
    gateway, _ = make({"leaky"}, up=False)
    _, body = gateway.call_tool("researcher", {"tool": "leaky", "args": {}})
    assert json.loads(body)["allow"] is False


def test_no_audit_record_no_call():
    gateway, logs = make({"leaky"}, audit=FailingSink())
    status, body = gateway.call_tool("researcher", {"tool": "leaky", "args": {}})
    assert status == 503 and "audit" in json.loads(body)["reason"]
    assert logs.observability.records == []


def test_tool_failure_is_reduced_to_its_class_name():
    gateway, logs = make({"broken"})
    _, body = gateway.call_tool("researcher", {"tool": "broken", "args": {}})
    assert json.loads(body)["output"] == "tool failed: RuntimeError" and "boom" not in body
    assert logs.observability.records[0]["error"] == "RuntimeError"


def test_bad_request_shape():
    gateway, _ = make({"leaky"})
    assert gateway.call_tool("researcher", {"tool": "../x", "args": {}})[0] == 400
    assert gateway.call_tool("researcher", {"tool": "leaky", "args": []})[0] == 400


def test_fetch_arguments_are_normalised_before_the_policy_sees_them():
    from tesseraline_airlock.fetch import make_fetch

    logs = Logs(MemorySink(), MemorySink(), MemorySink())
    policy = FakePolicy(set())
    gateway = Gateway(policy=policy, store=StaticStore({}), egress=None, tools=[make_fetch()], logs=logs)
    gateway.call_tool("researcher", {"tool": "fetch", "args": {"url": "HTTPS://Example.COM/a"}})
    assert policy.asked[-1]["args"] == {"url": "https://example.com/a", "host": "example.com"}
    _, body = gateway.call_tool("researcher", {"tool": "fetch", "args": {"url": "https://a@b.example/"}})
    assert "user info" in json.loads(body)["reason"]
    assert logs.audit.records[-1]["decision"] == "deny"


class Initials:
    def redact(self, text):
        return text.replace("Jan Kowalski", "[person]"), text.count("Jan Kowalski")


class Broken:
    def redact(self, text):
        raise RuntimeError("detector down")


@tool()
def person(args, context):
    return "owner: Jan Kowalski"


def test_redactor_runs_on_tool_output_and_fails_closed():
    logs = Logs(MemorySink(), MemorySink(), MemorySink())
    gateway = Gateway(
        policy=FakePolicy({"person"}),
        store=StaticStore({}),
        egress=None,
        tools=[person],
        logs=logs,
        redactor=Initials(),
    )
    _, body = gateway.call_tool("researcher", {"tool": "person", "args": {}})
    assert json.loads(body)["output"] == "owner: [person]"
    assert logs.observability.records[-1]["output"]["redacted"] == 1
    gateway.redactor = Broken()
    _, body = gateway.call_tool("researcher", {"tool": "person", "args": {}})
    assert "Jan Kowalski" not in body


def test_model_requests_carry_the_token_count_to_the_policy():
    policy = FakePolicy({"model:demo"})
    gateway = Gateway(policy=policy, store=StaticStore({}), egress=None, tools=[], logs=Logs.none())
    gateway.tokens.add("researcher", 1234)
    gateway.begin("researcher", "model:demo", {"path": "/", "model": ""}, "", {}, kind="model")
    assert policy.asked[-1]["tokens_last_hour"] == 1234
    gateway.call_tool("researcher", {"tool": "model:demo", "args": {}})
    assert "tokens_last_hour" not in policy.asked[-1]
