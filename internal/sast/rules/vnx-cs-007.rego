package vulnetix.rules.vnx_cs_007

import rego.v1

metadata := {
	"id": "VNX-CS-007",
	"name": "C# path traversal via Path.Combine with user input",
	"description": "Path.Combine is called with a user-supplied segment without prior validation that the resulting path stays within the intended directory. An attacker can supply '../' sequences to read or write files outside the intended directory.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-007/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["path-traversal", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

_request_sources := {
	"Request.",
	"HttpContext.",
	"queryString",
	"FormData",
	"RouteData",
	".Query[",
	".Form[",
	".Params[",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "Path.Combine")
	# Check that same line or surrounding lines have a request/user-input source
	window_start := max([0, i - 5])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	some src in _request_sources
	contains(window, src)
	# Not already validated with GetFileName
	not contains(window, "Path.GetFileName")
	not contains(window, "GetFullPath")
	finding := {
		"rule_id": metadata.id,
		"message": "Path.Combine used with potentially user-controlled input; validate with Path.GetFileName() or check that the resolved path starts with the expected base directory to prevent path traversal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
