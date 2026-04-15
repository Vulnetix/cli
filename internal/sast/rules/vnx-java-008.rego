package vulnetix.rules.vnx_java_008

import rego.v1

metadata := {
	"id": "VNX-JAVA-008",
	"name": "Java server-side request forgery",
	"description": "Constructing URLs from user input (request.getParameter) for server-side HTTP requests enables SSRF, allowing attackers to access internal services, cloud metadata endpoints, or perform port scanning.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-008/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
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
	"new URL(request.getParameter",
	"new URL(req.getParameter",
	"URI.create(request.getParameter",
	"HttpURLConnection) new URL(request",
	"RestTemplate().getForObject(request.getParameter",
	"WebClient.create(request.getParameter",
	"openConnection()",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ssrf_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used to construct server-side URL; validate against an allowlist of permitted hosts",
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`new\s+URL\(.*getParameter`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used to construct server-side URL; validate against an allowlist of permitted hosts",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
