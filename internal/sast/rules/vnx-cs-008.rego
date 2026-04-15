package vulnetix.rules.vnx_cs_008

import rego.v1

metadata := {
	"id": "VNX-CS-008",
	"name": "C# SSRF via WebClient or HttpClient with user-supplied URL",
	"description": "WebClient, HttpClient, or WebRequest is invoked with a URL derived from user-supplied input without host validation. An attacker can supply an internal URL to access internal services or cloud metadata endpoints (SSRF).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-008/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1090"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ssrf", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

_http_methods := {
	"OpenRead",
	"OpenReadAsync",
	"DownloadString",
	"DownloadStringAsync",
	"DownloadData",
	"DownloadDataAsync",
	"UploadString",
	"UploadData",
	"GetAsync",
	"PostAsync",
	"SendAsync",
	"GetStringAsync",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some method in _http_methods
	contains(line, method)
	# Flag when the argument looks like a variable rather than a string literal
	regex.match(`\.(` + method + `)\s*\(\s*[^"]`, line)
	# Context: check for WebClient, HttpClient, WebRequest within nearby lines
	window_start := max([0, i - 10])
	window_end := min([count(lines) - 1, i + 2])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	regex.match(`WebClient|HttpClient|WebRequest|HttpWebRequest`, window)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("HTTP client method %s called with a non-literal URL; validate that the host is in an allowlist before issuing the request to prevent SSRF", [method]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
