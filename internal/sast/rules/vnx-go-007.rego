package vulnetix.rules.vnx_go_007

import rego.v1

metadata := {
	"id": "VNX-GO-007",
	"name": "Go path traversal",
	"description": "Using user input (r.FormValue, r.URL.Query) to construct file paths without validation enables path traversal attacks, allowing attackers to read or write arbitrary files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-007/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["path-traversal", "file-access", "lfi"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_path_indicators := {
	"os.Open(r.FormValue",
	"os.ReadFile(r.FormValue",
	"filepath.Join(r.FormValue",
	"os.Open(r.URL.Query",
	"os.ReadFile(r.URL.Query",
	"http.ServeFile(w, r, r.FormValue",
	"http.ServeFile(w, r, r.URL.Query",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _path_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used in file path; validate and sanitize the path to prevent directory traversal",
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
	regex.match(`(os\.Open|os\.ReadFile|os\.Create|filepath\.Join)\(.*r\.(FormValue|URL\.Query)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used in file path; validate and sanitize the path to prevent directory traversal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
