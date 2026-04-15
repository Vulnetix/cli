package vulnetix.rules.vnx_c_002

import rego.v1

metadata := {
	"id": "VNX-C-002",
	"name": "Format string injection via non-literal format argument",
	"description": "printf, fprintf, sprintf, syslog, or similar format-string functions are called with a non-literal first format argument, allowing an attacker who controls the format string to read from or write to arbitrary memory locations.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-002/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [134],
	"capec": ["CAPEC-135"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["format-string", "c", "injection", "memory-safety"],
}

_is_c(path) if endswith(path, ".c")

_is_c(path) if endswith(path, ".h")

_is_c(path) if endswith(path, ".cpp")

_is_c(path) if endswith(path, ".cc")

_is_c(path) if endswith(path, ".cxx")

# printf/wprintf/vprintf family - format is 1st arg; flag if arg is not a string literal
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(printf|wprintf|vprintf|vwprintf|printk)\s*\(`, line)
	not regex.match(`\b(printf|wprintf|vprintf|vwprintf|printk)\s*\(\s*"`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Format string is not a string literal; an attacker controlling the format string can exploit %n to write to memory - pass a literal format string such as printf(\"%s\", user_input)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# fprintf/sprintf/syslog/dprintf family - format is 2nd arg
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(fprintf|sprintf|vsprintf|asprintf|vasprintf|dprintf|vdprintf|wsprintf|syslog|vsyslog)\s*\(`, line)
	not regex.match(`\b(fprintf|sprintf|vsprintf|asprintf|vasprintf|dprintf|vdprintf|wsprintf|syslog|vsyslog)\s*\([^,]+,\s*"`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Format string is not a string literal; use a fixed format string like fprintf(stream, \"%s\", user_input) to prevent format string injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
