package vulnetix.rules.vnx_c_003

import rego.v1

metadata := {
	"id": "VNX-C-003",
	"name": "OS command injection via system() or popen() with non-literal argument",
	"description": "system(), popen(), p2open(), or wordexp() is called with an argument that is not a string literal, meaning user-controlled input may be interpreted as a shell command. Use execve/execvp with argument arrays and never pass user input to a shell.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-003/",
	"languages": ["c", "cpp"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [78, 88, 676],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["command-injection", "c", "os-command", "shell"],
}

_is_c(path) if endswith(path, ".c")

_is_c(path) if endswith(path, ".h")

_is_c(path) if endswith(path, ".cpp")

_is_c(path) if endswith(path, ".cc")

_is_c(path) if endswith(path, ".cxx")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(system|popen|p2open|wordexp)\s*\(`, line)
	not regex.match(`\b(system|popen|p2open|wordexp)\s*\(\s*"`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "system()/popen() with non-literal argument enables OS command injection; replace with execve()/execvp() using argument arrays, or validate and sanitize the command string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
