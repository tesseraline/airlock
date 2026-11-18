package airlock.tools_test

import data.airlock.tools
import rego.v1

call(tool, args) := {"kind": "tool", "agent": "researcher", "tool": tool, "args": args, "calls_last_hour": 0}

test_fetch_allowed_host if {
	tools.decision.allow with input as call("fetch", {"url": "https://example.com/", "host": "example.com"})
}

test_fetch_other_host_refused if {
	d := tools.decision with input as call("fetch", {"url": "https://evil.example/", "host": "evil.example"})
	not d.allow
	d.reason == "arguments refused for fetch"
}

test_tool_not_given if {
	d := tools.decision with input as call("send_mail", {})
	d.reason == "tool send_mail is not given to agent researcher"
}

test_unknown_agent if {
	d := tools.decision with input as object.union(call("fetch", {"host": "example.com"}), {"agent": "stranger"})
	d.reason == "agent stranger is not known to the policy"
}

test_limit if {
	d := tools.decision with input as object.union(call("fetch", {"host": "example.com"}), {"calls_last_hour": 30})
	d.reason == "limit of 30 calls an hour reached for fetch"
}

test_model_route_and_model_list if {
	tools.decision.allow with input as {
		"kind": "model", "agent": "researcher", "tool": "model:demo",
		"args": {"path": "/v1/messages", "model": "demo-1"}, "calls_last_hour": 0,
	}
	not tools.decision.allow with input as {
		"kind": "model", "agent": "researcher", "tool": "model:demo",
		"args": {"path": "/v1/messages", "model": "big-expensive"}, "calls_last_hour": 0,
	}
}

test_kind_tool_cannot_use_model_rule if {
	not tools.decision.allow with input as call("model:demo", {"model": ""})
}

test_token_budget if {
	d := tools.decision with input as {
		"kind": "model", "agent": "researcher", "tool": "model:demo",
		"args": {"path": "/v1/messages", "model": "demo-1"}, "calls_last_hour": 0, "tokens_last_hour": 50000,
	}
	d.reason == "token budget of 50000 an hour used up for agent researcher"
}

test_tool_calls_ignore_the_token_budget if {
	tools.decision.allow with input as object.union(call("fetch", {"host": "example.com"}), {"tokens_last_hour": 999999})
}
