package vulnetix.rules.vnx_go_005

import rego.v1

metadata := {
	"id": "VNX-GO-005",
	"name": "Go open redirect",
	"description": "Passing user-controlled input (r.URL.Query, r.FormValue) directly to http.Redirect allows attackers to redirect users to malicious sites for phishing.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-005/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1566"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["open-redirect", "web", "phishing"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_redirect_indicators := {
	"http.Redirect(w, r, r.URL.Query",
	"http.Redirect(w, r, r.FormValue",
	"http.Redirect(w, r, r.URL.Path",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _redirect_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input passed directly to http.Redirect; validate the URL against an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`http\.Redirect\(.*r\.(FormValue|URL\.Query)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input passed directly to http.Redirect; validate the URL against an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
