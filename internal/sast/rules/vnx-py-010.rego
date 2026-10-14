package vulnetix.rules.vnx_py_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-010",
	"name": "SSL verification disabled in requests",
	"description": "TLS certificate verification is turned off for an HTTP client in the requests or httpx style, so any host on the network path can impersonate the server and read or alter the traffic. Reported, in a Python file that imports requests or httpx (also under an alias): verify=False passed to an HTTP request call (requests.get/post/put/patch/delete/head/options/request, Session methods, httpx.get/stream, client.send) or to an httpx Client, AsyncClient or HTTPTransport, including when the argument sits on a continuation line of a multi-line call; and a session or client whose .verify attribute is assigned False. Not reported: verify=True, a CA bundle path, a setting or certifi.where(), verify=False passed to a non-HTTP call (jwt.decode, form.validate), test files, and the pattern inside strings and comments. urllib3, aiohttp and ssl-module contexts are covered by VNX-CRYPTO-005.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-010/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["tls", "ssl", "mitm", "requests"],
}

# Strings blanked and trailing comments dropped: a log message or a help text
# naming verify=False is not a call.
_strip(line) := regex.replace(
	regex.replace(line, `"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'`, `""`),
	`#.*$`,
	"",
)

_off_re := `(?:^|[^\w])verify\s*=\s*False\b`

# An HTTP request method or an httpx client/transport constructor.
_http_call_re := `(?:\.(?:get|post|put|patch|delete|head|options|request|send|stream)|(?:^|[^\w])(?:Client|AsyncClient|HTTPTransport|AsyncHTTPTransport))\s*\(`

# Collapse balanced parentheses three levels deep, so an argument such as
# headers=h() does not look like the call closing.
_collapse(s) := regex.replace(regex.replace(regex.replace(s, `\([^()]*\)`, "_"), `\([^()]*\)`, "_"), `\([^()]*\)`, "_")

# verify=False on line i is an argument of an HTTP call that opens on line i or
# up to 8 lines above and is still open where the keyword appears.
_in_http_call(lines, i, code) if {
	before := regex.split(`verify\s*=\s*False\b`, code)[0]
	prev := [_strip(lines[k]) | some k in numbers.range(max([0, i - 8]), i - 1); i > 0; not helpers.is_comment_line(lines[k])]
	txt := concat("\n", array.concat(prev, [before]))
	pieces := regex.split(_http_call_re, txt)
	count(pieces) > 1
	rest := pieces[count(pieces) - 1]
	not contains(_collapse(rest), ")")
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "TLS certificate verification disabled (verify=False): any host on the network path can impersonate the server and read or modify the traffic; remove verify=False or pass the path of the CA bundle that signs the server certificate",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_http_lib(content) if regex.match(`(?m)^\s*(?:import\s+(?:requests|httpx)\b|from\s+(?:requests|httpx)\b)`, content)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "verify")
	not helpers.is_test_path(path)
	_http_lib(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "verify")
	not helpers.is_comment_line(line)
	code := _strip(line)
	regex.match(_off_re, code)
	not regex.match(`\.verify\s*=\s*False`, code)
	_in_http_call(lines, i, code)
	finding := _finding(path, i, line)
}

# session.verify = False / client.verify = False
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "verify")
	not helpers.is_test_path(path)
	_http_lib(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "verify")
	regex.match(`^\s*[A-Za-z_][\w\.\[\]"']*\.verify\s*=\s*False\b`, _strip(line))
	finding := _finding(path, i, line)
}
