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
	tools.decision.allow with input as object.union(call("fetch", {"url": "https://example.com/", "host": "example.com"}), {"tokens_last_hour": 999999})
}

test_list_shows_only_the_agents_tools if {
	d := tools.decision with input as {"kind": "list", "agent": "researcher"}
	d.tools == ["fetch", "model:demo"]
}

test_list_for_an_unknown_agent_is_empty if {
	d := tools.decision with input as {"kind": "list", "agent": "stranger"}
	d.tools == []
}

fetch(url) := call("fetch", {"url": url})

test_acl_host_entry_covers_the_whole_host if {
	tools.decision.allow with input as fetch("https://example.com/docs/page?x=1")
}

test_acl_path_entry_covers_only_whole_segments if {
	tools.decision.allow with input as fetch("https://github.com/tesseraline")
	tools.decision.allow with input as fetch("https://github.com/tesseraline/airlock/blob/production/README.md")
	not tools.decision.allow with input as fetch("https://github.com/tesseraline-evil/x")
	not tools.decision.allow with input as fetch("https://github.com/someone/else")
}

test_acl_deny_wins if {
	not tools.decision.allow with input as fetch("https://example.com/blog")
	not tools.decision.allow with input as fetch("https://example.com/blog/2026/post")
	not tools.decision.allow with input as fetch("https://example.com/about-us?ref=x")
	tools.decision.allow with input as fetch("https://example.com/blogger")
}

test_acl_port_and_lookalike_hosts if {
	tools.decision.allow with input as fetch("https://demo-api:8443/items")
	not tools.decision.allow with input as fetch("https://demo-api/items")
	not tools.decision.allow with input as fetch("https://example.com.evil.test/")
	not tools.decision.allow with input as fetch("https://example.com:8443/")
}
