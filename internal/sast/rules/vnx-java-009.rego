package vulnetix.rules.vnx_java_009

import rego.v1

metadata := {
	"id": "VNX-JAVA-009",
	"name": "Java path traversal",
	"description": "Constructing file paths from user input (request.getParameter) without validation enables path traversal attacks, allowing attackers to read or write arbitrary files on the server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-009/",
	"languages": ["java"],
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

_path_traversal_indicators := {
	"new File(request.getParameter",
	"new File(req.getParameter",
	"new FileInputStream(request.getParameter",
	"new FileReader(request.getParameter",
	"Paths.get(request.getParameter",
	"Files.readAllBytes(Paths.get(request",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _path_traversal_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used in file path; validate and canonicalize the path to prevent directory traversal",
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
	regex.match(`new\s+File\(.*getParameter`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used in file path; validate and canonicalize the path to prevent directory traversal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
