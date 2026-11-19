# The first door. The gateway asks before every tool call and every model request.
# Input: kind ("tool" or "model"), agent (from its certificate), tool, args (already normalised by the gateway),
# calls_last_hour (counted by the gateway for this agent and tool). Data: data.json next to this file.
package airlock.tools

import rego.v1

default allow := false

allow if {
	input.tool in data.agents[input.agent].tools
	args_ok
	not over_limit
	not over_budget
}

# fetch: an access list per agent. A URL passes when it is under an `allow` entry and under no `deny` entry.
# "Under" means the entry itself or anything below it at a whole path segment: "https://github.com/tesseraline"
# covers /tesseraline and /tesseraline/airlock, not /tesseraline-evil. "https://example.com" covers the whole host.
# The gateway has normalised the URL already: lower-case host, no user info, no dot segments, no encoded slashes.
fetch_acl := object.get(data.agents[input.agent], "fetch", {})

args_ok if {
	input.tool == "fetch"
	some entry in object.get(fetch_acl, "allow", [])
	under(input.args.url, entry)
	not fetch_denied
}

fetch_denied if {
	some entry in object.get(fetch_acl, "deny", [])
	under(input.args.url, entry)
}

under(url, entry) if url == trim_suffix(entry, "/")

under(url, entry) if startswith(url, concat("", [trim_suffix(entry, "/"), "/"]))

under(url, entry) if startswith(url, concat("", [trim_suffix(entry, "/"), "?"]))

# a model route: any path under the route; the requested model, if named, must be on the agent's list
args_ok if {
	input.kind == "model"
	startswith(input.tool, "model:")
	model_ok
}

model_ok if input.args.model == ""

model_ok if input.args.model in data.agents[input.agent].models

over_limit if input.calls_last_hour >= object.get(data.limits, input.tool, data.limits.default)

# model routes: a token budget per agent and hour, measured by the gateway on earlier answers
over_budget if {
	input.kind == "model"
	input.tokens_last_hour >= object.get(data.agents[input.agent], "tokens_per_hour", data.limits.tokens_per_hour)
}

# the tools an agent may see in an MCP tools/list; the same data as the decisions below
visible := sort([t | some t in object.get(data.agents, input.agent, {"tools": []}).tools])

decision := {"allow": true, "reason": "listed", "tools": visible, "version": data.version} if input.kind == "list"

decision := {"allow": true, "reason": "allowed", "version": data.version} if {
	input.kind != "list"
	allow
}

decision := {"allow": false, "reason": why_not, "version": data.version} if {
	input.kind != "list"
	not allow
}

why_not := sprintf("agent %s is not known to the policy", [input.agent]) if {
	not data.agents[input.agent]
} else := sprintf("tool %s is not given to agent %s", [input.tool, input.agent]) if {
	not input.tool in data.agents[input.agent].tools
} else := sprintf("limit of %d calls an hour reached for %s", [object.get(data.limits, input.tool, data.limits.default), input.tool]) if {
	over_limit
} else := sprintf("token budget of %d an hour used up for agent %s", [object.get(data.agents[input.agent], "tokens_per_hour", data.limits.tokens_per_hour), input.agent]) if {
	over_budget
} else := sprintf("arguments refused for %s", [input.tool])
