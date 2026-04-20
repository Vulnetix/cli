# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1333

import rego.v1

metadata := {
	"id": "VNX-1333",
	"name": "Inefficient Regular Expression Complexity (ReDoS)",
	"description": "Regular expressions with catastrophic backtracking patterns are used, potentially on user-supplied input. Patterns such as (a+)+, (a|aa)+, or nested quantifiers can cause exponential evaluation time when matched against crafted inputs, leading to denial of service (ReDoS).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1333/",
	"languages": ["python", "javascript", "java", "go", "php", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [1333],
	"capec": ["CAPEC-492"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["redos", "regex", "denial-of-service", "backtracking", "cwe-1333"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Catastrophic backtracking patterns in regex literals
_redos_patterns := {
	"(a+)+",
	"(a|aa)+",
	"([a-z]+)*",
	"([a-zA-Z]+)*",
	"(\\w+)+",
	"(\\d+)+",
	"(.+)+",
	"([a-z]*)*",
	"(\\w*)*",
	"([^/]+)+",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _redos_patterns
	contains(line, p)
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Catastrophic backtracking regex pattern '%s' detected; this pattern has exponential worst-case matching time — rewrite using possessive quantifiers, atomic groups, or a linear-time regex engine", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Python re.compile with user input applied
_py_regex_compile_patterns := {
	"re.compile(",
	"re.match(",
	"re.search(",
	"re.fullmatch(",
	"re.findall(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _py_regex_compile_patterns
	contains(line, p)
	contains(line, "user")
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Regex function '%s' applied to user-supplied input; verify the pattern cannot exhibit catastrophic backtracking, or use re2 / timeout enforcement to bound execution time", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Node.js: regex applied to user input
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, ".test(req.")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": "Regex .test() applied to user request data; ensure the regex pattern is not susceptible to ReDoS — use validator.js, safe-regex, or re2 for untrusted input",
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, ".match(req.")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": "Regex .match() applied to user request data; ensure the regex pattern is not susceptible to ReDoS — use safe-regex or re2 for untrusted input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
