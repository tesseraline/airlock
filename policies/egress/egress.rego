# The second door. Envoy asks before any request leaves; the gateway sends the destination in the Host header.
# Only hosts on the list, only the methods each host allows, and optionally only some paths: `allow` and `deny`
# list path entries that cover themselves and everything below at a whole segment ("/" is the whole host); deny
# wins. Envoy normalises the path before it asks. A refusal carries a header the gateway recognises.
package airlock.egress

import rego.v1

default allow := false

request := input.attributes.request.http

authority := lower(request.host)

rule := data.hosts[authority]

allow if {
	request.method in rule.methods
	some entry in object.get(rule, "allow", ["/"])
	path_under(request.path, entry)
	not path_denied
}

path_denied if {
	some entry in object.get(rule, "deny", [])
	path_under(request.path, entry)
}

path_under(path, entry) if path == trim_suffix(entry, "/")

path_under(path, entry) if startswith(path, concat("", [trim_suffix(entry, "/"), "/"]))

path_under(path, entry) if startswith(path, concat("", [trim_suffix(entry, "/"), "?"]))

result := {"allowed": true} if allow

result := {
	"allowed": false,
	"http_status": 403,
	"headers": {"x-airlock-egress": "denied"},
	"body": sprintf("egress to %s refused by policy", [authority]),
} if not allow
