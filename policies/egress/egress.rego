# The second door. Envoy asks before any request leaves; the gateway sends the destination in the Host header.
# Only hosts on the list, only the methods each host allows. A refusal carries a header the gateway recognises.
package airlock.egress

import rego.v1

default allow := false

request := input.attributes.request.http

authority := lower(request.host)

allow if request.method in object.get(data.hosts, authority, [])

result := {"allowed": true} if allow

result := {
	"allowed": false,
	"http_status": 403,
	"headers": {"x-airlock-egress": "denied"},
	"body": sprintf("egress to %s refused by policy", [authority]),
} if not allow
