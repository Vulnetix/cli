# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1048

import rego.v1

metadata := {
	"id": "VNX-1048",
	"name": "Invokable Control Element with Large Number of Outgoing Control Flow Transfers",
	"description": "A function or method with excessive cyclomatic complexity (large numbers of branches, loops, and conditions) is difficult to reason about, test, and audit for security properties. Security-critical functions with high complexity frequently contain untested code paths that may bypass security controls.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1048/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1048],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cyclomatic-complexity", "code-quality", "maintainability", "cwe-1048"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Branch-adding keywords
_branch_keywords := {
	" if ",
	" else ",
	" elif ",
	" for ",
	" while ",
	" case ",
	" catch ",
	" || ",
	" && ",
	"? ",
}

# Function definition markers
_func_def_patterns := {
	"def ",
	"function ",
	"func ",
	"public ",
	"private ",
	"protected ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some fp in _func_def_patterns
	contains(line, fp)
	contains(line, "(")
	# Count branches in next 50 lines
	branch_count := count([j |
		j := numbers.range(i+1, i+50)[_]
		j < count(lines)
		some bp in _branch_keywords
		contains(lines[j], bp)
	])
	branch_count >= 15
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function starting with '%s' has approximately %d control flow branches in its body; high cyclomatic complexity makes security properties hard to verify. Refactor into smaller functions", [fp, branch_count]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
