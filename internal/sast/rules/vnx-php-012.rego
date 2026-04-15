package vulnetix.rules.vnx_php_012

import rego.v1

metadata := {
	"id": "VNX-PHP-012",
	"name": "PHP reflected XSS via echo/print of user input",
	"description": "User-controlled input from superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE) is passed directly to echo, print, or printf without HTML encoding. This allows attackers to inject arbitrary JavaScript or HTML into the page. Use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before all output.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-012/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1189"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["xss", "injection", "php"],
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
	regex.match(`^\s*echo\s+`, line)
	regex.match(`\$_(GET|POST|REQUEST|COOKIE)\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Reflected XSS: user input echoed without HTML encoding — use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before output",
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
	regex.match(`^\s*print\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Reflected XSS: user input passed to print() without HTML encoding — use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before output",
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
	regex.match(`^\s*printf\s*\(`, line)
	regex.match(`\$_(GET|POST|REQUEST|COOKIE)\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Reflected XSS: user input passed to printf() without HTML encoding — use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before output",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
