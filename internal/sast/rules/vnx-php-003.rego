package vulnetix.rules.vnx_php_003

import rego.v1

metadata := {
	"id": "VNX-PHP-003",
	"name": "PHP file inclusion with variable path",
	"description": "include, require, include_once, and require_once with a variable or user-controlled path enable Local File Inclusion (LFI) and potentially Remote File Inclusion (RFI), leading to arbitrary code execution.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PHP-003",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [98],
	"capec": ["CAPEC-193"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["file-inclusion", "lfi", "rfi", "rce"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "File inclusion with user-controlled path (LFI/RFI); use a whitelist of allowed files instead",
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(include|require|include_once|require_once)\s*\(\s*\$[a-zA-Z_]+\s*\.`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "File inclusion with variable path; validate the path against an allowlist of permitted files",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
