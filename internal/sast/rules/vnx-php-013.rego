package vulnetix.rules.vnx_php_013

import rego.v1

metadata := {
	"id": "VNX-PHP-013",
	"name": "PHP XXE via LIBXML_NOENT or LIBXML_DTDLOAD flag",
	"description": "simplexml_load_string() or simplexml_load_file() is called with LIBXML_NOENT or LIBXML_DTDLOAD flags, enabling XML external entity (XXE) expansion. Attackers can read arbitrary server files (e.g. /etc/passwd) or perform server-side request forgery. Call libxml_disable_entity_loader(true) and avoid these flags.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-013/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-221"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["xxe", "xml", "php"],
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
	regex.match(`simplexml_load_(string|file)\s*\(`, line)
	contains(line, "LIBXML_NOENT")
	finding := {
		"rule_id": metadata.id,
		"message": "XXE: LIBXML_NOENT enables external entity expansion; call libxml_disable_entity_loader(true) and remove this flag",
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
	regex.match(`simplexml_load_(string|file)\s*\(`, line)
	contains(line, "LIBXML_DTDLOAD")
	finding := {
		"rule_id": metadata.id,
		"message": "XXE: LIBXML_DTDLOAD enables DTD processing and external entity expansion; call libxml_disable_entity_loader(true) and remove this flag",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
