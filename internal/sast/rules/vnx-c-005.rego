package vulnetix.rules.vnx_c_005

import rego.v1

metadata := {
	"id": "VNX-C-005",
	"name": "Integer overflow in malloc/calloc size arithmetic",
	"description": "malloc(), calloc(), realloc(), or aligned_alloc() is called with an arithmetic expression (multiplication or addition) as the size argument without prior overflow checks. Integer overflow in the size calculation can result in undersized allocations and subsequent heap buffer overflows.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-c-005/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [190, 131, 787],
	"capec": ["CAPEC-92"],
	"attack_technique": ["T1203"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["integer-overflow", "c", "malloc", "memory-safety"],
}

_is_c(path) if endswith(path, ".c")

_is_c(path) if endswith(path, ".h")

_is_c(path) if endswith(path, ".cpp")

_is_c(path) if endswith(path, ".cc")

_is_c(path) if endswith(path, ".cxx")

# malloc/valloc with arithmetic in the single size argument
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(malloc|valloc)\s*\([^)]*[+*][^)]*\)`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Arithmetic in malloc() size argument may overflow; validate the result with checked multiplication (e.g., if (n > SIZE_MAX / elem_size) or use calloc(n, elem_size) which performs the check internally)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# calloc/realloc/aligned_alloc with arithmetic in either size argument
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_c(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(realloc|aligned_alloc)\s*\([^)]*[+*][^)]*\)`, line)
	not regex.match(`^\s*(//|/\*)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Arithmetic in realloc()/aligned_alloc() size argument may overflow; validate sizes before passing to allocators",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
