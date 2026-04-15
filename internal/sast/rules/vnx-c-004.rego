package vulnetix.rules.vnx_c_004

import rego.v1

metadata := {
	"id": "VNX-C-004",
	"name": "Use-after-free: pointer used after free()",
	"description": "A pointer is dereferenced, passed to a function, or returned after being freed. Use-after-free bugs can lead to memory corruption, crashes, or arbitrary code execution. Set the pointer to NULL immediately after free() and never access freed memory.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-004/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [416],
	"capec": ["CAPEC-123"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["use-after-free", "c", "memory-safety", "heap"],
}

_is_c(path) if endswith(path, ".c")

_is_c(path) if endswith(path, ".h")

_is_c(path) if endswith(path, ".cpp")

_is_c(path) if endswith(path, ".cc")

_is_c(path) if endswith(path, ".cxx")

# Detect free(ptr) immediately followed by a use of the same identifier on the very next non-blank line.
# We look for the pattern: a line contains free(<id>) and the next few lines reference that same <id>
# without reassignment in between. We use a windowed two-line check for single-line detectable patterns.
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	# Extract the freed pointer name
	m := regex.find_n(`\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`, line, 1)
	count(m) > 0
	# Check the next line (i+1) for use of the same identifier
	next_line := lines[i + 1]
	ptr_name := regex.find_n(`\bfree\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)`, line, 1)[0]
	# Extract just the pointer name from the match
	ptr := regex.find_n(`[a-zA-Z_][a-zA-Z0-9_]*`, ptr_name, -1)[1]
	regex.match(concat("", [`\b`, ptr, `\b`]), next_line)
	not regex.match(concat("", [`\b`, ptr, `\s*=\s*`]), next_line)
	not regex.match(concat("", [`\bfree\s*\(\s*`, ptr, `\s*\)`]), next_line)
	not regex.match(`^\s*(//|/\*)`, next_line)
	finding := {
		"rule_id": metadata.id,
		"message": "Pointer appears to be used after free(); set pointer to NULL after free() and add a NULL check before any subsequent use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 2,
		"snippet": next_line,
	}
}
