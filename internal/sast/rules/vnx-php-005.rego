package vulnetix.rules.vnx_php_005

import rego.v1

metadata := {
	"id": "VNX-PHP-005",
	"name": "PHP server-side request forgery",
	"description": "Using user input ($_GET, $_POST) in file_get_contents(), curl_setopt CURLOPT_URL, or fopen() enables SSRF attacks against internal services.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-005/",
	"languages": ["php"],
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
	"file_get_contents($_GET",
	"file_get_contents($_POST",
	"file_get_contents($_REQUEST",
	"fopen($_GET",
	"fopen($_POST",
	"fopen($_REQUEST",
	"CURLOPT_URL, $_GET",
	"CURLOPT_URL, $_POST",
	"CURLOPT_URL, $_REQUEST",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ssrf_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input used in server-side HTTP request; validate against an allowlist of permitted hosts",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
