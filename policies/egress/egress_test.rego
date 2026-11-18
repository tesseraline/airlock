package airlock.egress_test

import data.airlock.egress
import rego.v1

req(host, method) := {"attributes": {"request": {"http": {"host": host, "method": method, "path": "/"}}}}

test_allowed if egress.result.allowed with input as req("Example.com", "GET")

test_method_not_allowed if not egress.result.allowed with input as req("example.com", "POST")

test_other_host if {
	r := egress.result with input as req("evil.example", "GET")
	not r.allowed
	r.headers["x-airlock-egress"] == "denied"
}

test_port_is_part_of_the_host if not egress.result.allowed with input as req("example.com:8443", "GET")
