package vulnetix.rules.vnx_php_004

import rego.v1

metadata := {
	"id": "VNX-PHP-004",
	"name": "PHP open redirect",
	"description": "Passing user input ($_GET, $_POST, $_REQUEST) directly to header('Location: ...') or redirect() allows attackers to redirect users to malicious sites.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-004/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
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
	"header(\"Location: \" . $_GET",
	"header(\"Location: \" . $_POST",
	"header(\"Location: \" . $_REQUEST",
	"header('Location: ' . $_GET",
	"header('Location: ' . $_POST",
	"header('Location: ' . $_REQUEST",
	"redirect($_GET[",
	"redirect($_POST[",
	"redirect($_REQUEST[",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _redirect_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input passed directly to redirect; validate the URL against an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
