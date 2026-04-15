package vulnetix.rules.vnx_php_007

import rego.v1

metadata := {
	"id": "VNX-PHP-007",
	"name": "PHP extract on superglobal",
	"description": "Using extract() on superglobals ($_GET, $_POST, $_REQUEST) imports user-controlled data as local variables, enabling variable overwriting attacks that can bypass security checks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-007/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [621],
	"capec": ["CAPEC-17"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["variable-overwrite", "injection", "php"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_extract_indicators := {
	"extract($_GET",
	"extract($_POST",
	"extract($_REQUEST",
	"extract($_COOKIE",
	"extract($_SERVER",
	"extract($_FILES",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _extract_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "extract() on superglobal allows variable overwriting attacks; use explicit variable assignments instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
