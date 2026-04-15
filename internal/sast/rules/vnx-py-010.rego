package vulnetix.rules.vnx_py_010

import rego.v1

metadata := {
	"id": "VNX-PY-010",
	"name": "SSL verification disabled in requests",
	"description": "requests.get/post with verify=False disables TLS certificate validation, enabling man-in-the-middle attacks on HTTPS connections.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PY-010",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tls", "ssl", "mitm", "requests"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`requests\.(get|post|put|patch|delete|head|options)\(.*verify\s*=\s*False`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SSL verification disabled (verify=False); remove the verify=False parameter to enable certificate validation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
