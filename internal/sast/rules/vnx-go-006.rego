package vulnetix.rules.vnx_go_006

import rego.v1

metadata := {
	"id": "VNX-GO-006",
	"name": "Go server-side request forgery",
	"description": "Using user input (r.FormValue, r.URL.Query) to construct HTTP requests enables SSRF, allowing attackers to access internal services or cloud metadata endpoints.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-006/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssrf", "web", "cloud"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_ssrf_indicators := {
	"http.Get(r.FormValue",
	"http.Get(r.URL.Query",
	"http.Post(r.FormValue",
	"http.NewRequest(\"GET\", r.FormValue",
	"http.NewRequest(\"POST\", r.FormValue",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ssrf_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used to construct server-side HTTP request; validate against an allowlist of permitted hosts",
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
	regex.match(`http\.(Get|Post|NewRequest)\(.*r\.(FormValue|URL\.Query)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used to construct server-side HTTP request; validate against an allowlist of permitted hosts",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
