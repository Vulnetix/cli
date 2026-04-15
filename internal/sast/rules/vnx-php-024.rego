package vulnetix.rules.vnx_php_024

import rego.v1

metadata := {
	"id": "VNX-PHP-024",
	"name": "PHP mb_ereg_replace with variable options enabling eval modifier",
	"description": "mb_ereg_replace() or mb_eregi_replace() is called with a variable as the options parameter. If that variable contains the 'e' modifier, PHP evaluates the replacement string as PHP code, enabling arbitrary code execution. Always pass a hardcoded string for the options parameter and never include 'e'.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-024/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["code-injection", "mb-ereg-replace", "eval", "php"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`mb_ereg(i)?_replace\s*\(`, line)
	not regex.match(`mb_ereg(i)?_replace\s*\([^,]+,[^,]+,[^,]+,\s*['"][^e'"]*['"]`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "mb_ereg_replace() called with non-literal options; the 'e' eval modifier executes the replacement as PHP code — always pass a literal options string and never include 'e'",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`mb_ereg(i)?_replace\s*\(`, line)
	regex.match(`mb_ereg(i)?_replace\s*\([^,]+,[^,]+,[^,]+,\s*['"][^'"]*e[^'"]*['"]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "mb_ereg_replace() options include the 'e' modifier which evaluates the replacement as PHP code — remove the 'e' modifier to prevent code injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
