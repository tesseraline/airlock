# Who may talk to the tools OPA: only the gateway's certificate, only to ask for a decision or the health check.
# Nobody can change policies or data over the API.
package system.authz

import rego.v1

default allow := false

gateway if input.identity == "CN=gateway"

allow if {
	gateway
	input.method == "POST"
	input.path == ["v1", "data", "airlock", "tools", "decision"]
}

allow if {
	gateway
	input.method == "GET"
	input.path == ["health"]
}
