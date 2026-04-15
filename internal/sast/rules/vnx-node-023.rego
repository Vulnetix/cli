package vulnetix.rules.vnx_node_023

import rego.v1

metadata := {
	"id": "VNX-NODE-023",
	"name": "Unsafe YAML.load() with untrusted input",
	"description": "js-yaml YAML.load() (or yaml.load() without safeLoad) deserializes JavaScript-specific types including custom constructors. An attacker-supplied YAML document can execute arbitrary code during parsing via !!js/eval or custom type constructors. Use YAML.safeLoad() or pass {schema: FAILSAFE_SCHEMA} or use js-yaml 4.x where load() requires an explicit schema.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-023/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["deserialization", "yaml", "js-yaml", "rce", "node"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`yaml\.load\s*\(`, line)
	not contains(line, "safeLoad")
	not contains(line, "FAILSAFE_SCHEMA")
	not contains(line, "JSON_SCHEMA")
	not contains(line, "CORE_SCHEMA")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "yaml.load() can execute arbitrary code when parsing untrusted YAML; use yaml.safeLoad() or specify a safe schema like FAILSAFE_SCHEMA",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_js(path)
	not endswith(path, ".min.js")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`YAML\.load\s*\(`, line)
	not contains(line, "FAILSAFE_SCHEMA")
	not contains(line, "JSON_SCHEMA")
	not contains(line, "CORE_SCHEMA")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "YAML.load() can execute arbitrary code when parsing untrusted YAML; use YAML.safeLoad() or specify {schema: FAILSAFE_SCHEMA}",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
