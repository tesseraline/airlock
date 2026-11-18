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

# fetch: the gateway sends the normalised host ("name" or "name:port")
args_ok if {
	input.tool == "fetch"
	input.args.host in data.agents[input.agent].fetch_hosts
}

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

decision := {"allow": true, "reason": "allowed", "version": data.version} if allow

decision := {"allow": false, "reason": why_not, "version": data.version} if not allow

why_not := sprintf("agent %s is not known to the policy", [input.agent]) if {
	not data.agents[input.agent]
} else := sprintf("tool %s is not given to agent %s", [input.tool, input.agent]) if {
	not input.tool in data.agents[input.agent].tools
} else := sprintf("limit of %d calls an hour reached for %s", [object.get(data.limits, input.tool, data.limits.default), input.tool]) if {
	over_limit
} else := sprintf("token budget of %d an hour used up for agent %s", [object.get(data.agents[input.agent], "tokens_per_hour", data.limits.tokens_per_hour), input.agent]) if {
	over_budget
} else := sprintf("arguments refused for %s", [input.tool])
