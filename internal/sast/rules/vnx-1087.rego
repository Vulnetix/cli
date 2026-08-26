# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1087

import rego.v1

metadata := {
	"id": "VNX-1087",
	"name": "Class with Virtual Method without a Virtual Destructor",
	"description": "Detects source patterns associated with CWE-1087 (Class with Virtual Method without a Virtual Destructor). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1087/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1087],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["invokable-element-missing-documentation", "cwe-1087"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".min.html")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
_is_comment_line(line) if startswith(trim_space(line), "--")

# A Python docstring is on the line *after* the signature, never on the `def`
# line itself, so `not contains(line, "\"\"\"")` was true for every function ever
# written and this rule fired on all of them. Anchoring on a real `def` and
# looking ahead past a multi-line signature for the docstring is what makes the
# finding mean what its message says.
_is_def(line) if regex.match(`^\s*(async\s+)?def\s+[A-Za-z_]`, line)

_docstring_start(line) if regex.match(`^\s*[rRbBuUfF]{0,2}("""|\x27\x27\x27)`, line)

# The signature may wrap over several lines. Find where it closes (the first
# line ending in `:`, ignoring a trailing comment), then the docstring — if
# there is one — is the first non-blank line of the body.
_sig_end(lines, i) := e if {
	end := min([count(lines) - 1, i + 12])
	cands := [k |
		some k in numbers.range(i, end)
		regex.match(`:\s*(#.*)?$`, lines[k])
	]
	count(cands) > 0
	e := cands[0]
}

_has_docstring(lines, i) if {
	e := _sig_end(lines, i)
	end := min([count(lines) - 1, e + 4])
	end >= e + 1
	body := [k |
		some k in numbers.range(e + 1, end)
		trim_space(lines[k]) != ""
	]
	count(body) > 0
	_docstring_start(lines[body[0]])
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	_is_def(line)
	not _has_docstring(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Function without docstring",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
