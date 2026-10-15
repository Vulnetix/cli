# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_706

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-706",
	"name": "Directory containment decided by a character prefix instead of a path prefix",
	"description": "A Python check that a resolved path lies inside a base directory compares strings character by character, so a sibling directory whose name merely starts with the base name (/srv/uploads-private, /var/www2) is resolved as inside it and passes. Reported: os.path.commonprefix(...) (also posixpath/ntpath and a from-imported commonprefix) compared with == or !=, which the Python docs warn works per character and not per path component; and str.startswith() on a canonicalised path (os.path.realpath/abspath/normpath(...) or str(Path.resolve()), inline or through a variable assigned from one in the 10 lines above) whose argument is a base directory without a trailing separator: a path literal not ending in /, a realpath/abspath/normpath/str(resolve()) call (which strips any trailing separator), or a name whose assignment in the file does not append os.sep or '/'. Not reported: os.path.commonpath, Path.is_relative_to, a prefix with + os.sep, os.path.join(base, '') or a trailing '/', a base variable assigned with a trailing separator, commonprefix used to compute a shared stem, startswith on a non-path literal ('tmp'), comments and string literals. Uncanonicalised prefix checks (base/../x) are VNX-41.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-706/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [706],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["path-equivalence", "path-traversal", "cwe-706"],
}

_args := `\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_canon_call := concat("", [`(?:\b(?:os\.path|posixpath|ntpath)\s*\.\s*)?\b(?:realpath|abspath|normpath)\s*`, _args])

_resolve_str := concat("", [`\bstr\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\.resolve\s*\([^()]*\)\s*\)?\s*\)`])

_sw := `\s*\.\s*startswith\s*\(\s*((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`

_inline_re := concat("", [`(?:`, _canon_call, `|`, _resolve_str, `)`, _sw])

# The line with string literals blanked. A hit must match on this text, so a
# call written inside a string is not code; the argument itself is read from
# the original line because its literal value matters.
_blank(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_sep_safe(arg) if regex.match(`os\.(?:path\.)?sep\b|os\.path\.join\s*\(.*,\s*(?:""|'')\s*\)|/["']\s*$|\+\s*["']/["']|\\\\["']\s*$`, arg)

# A bare literal argument is a directory only if it looks like a path.
_unsafe_arg(arg, _) if {
	regex.match(`^\s*["'][/\\~A-Za-z:.]*[/\\][^"']*["']\s*$`, arg)
	not _sep_safe(arg)
}

# realpath/abspath/normpath(...) and str(x.resolve()) strip any trailing
# separator, so a base canonicalised inline never ends in one.
_unsafe_arg(arg, _) if regex.match(concat("", [`^\s*(?:`, _canon_call, `|`, _resolve_str, `)\s*$`]), arg)

# A name (or str(name), self.name): unsafe unless an assignment of it in the
# file adds a separator.
_unsafe_arg(arg, content) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:str\s*\(\s*)?(?:self\.)?([A-Za-z_]\w*)(?:\.resolve\(\s*\))?\s*\)?\s*$`, arg, 1)
	count(m) > 0
	name := m[0][1]
	not _sep_assigned(content, name)
}

_sep_assigned(content, name) if {
	some a in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*(?:self\.)?`, name, `\s*=\s*(.*)$`]), content, -1)
	_sep_safe(a[1])
}

_msg := "This containment check compares characters, not path components: a sibling directory whose name starts with the base (base-private, base2) passes. Use os.path.commonpath([base, p]) == base, Path.is_relative_to(), or compare against base + os.sep"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "commonprefix")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "commonprefix")
	not helpers.is_comment_line(line)
	code := _blank(line)
	_commonprefix_call(code, content)
	regex.match(`[!=]=`, code)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_commonprefix_call(code, _) if regex.match(`\b(?:os\.path|posixpath|ntpath)\s*\.\s*commonprefix\s*\(`, code)

_commonprefix_call(code, content) if {
	regex.match(`(?:^|[^\w.])commonprefix\s*\(`, code)
	regex.match(`(?m)^\s*from\s+(?:os\.path|posixpath|ntpath)\s+import\s+.*\bcommonprefix\b`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "startswith")
	regex.match(`realpath|abspath|normpath|\.resolve\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "startswith")
	not helpers.is_comment_line(line)
	regex.match(_inline_re, _blank(line))
	some m in regex.find_all_string_submatch_n(_inline_re, line, -1)
	_unsafe_arg(m[1], content)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_canon_rhs := concat("", [`^\s*(?:`, _canon_call, `|\(?.*\.resolve\s*\([^()]*\)\s*\)?|str\s*\(.*\.resolve\s*\([^()]*\)\s*\))\s*$`])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "startswith")
	regex.match(`realpath|abspath|normpath|\.resolve\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "startswith")
	not helpers.is_comment_line(line)
	not regex.match(_inline_re, _blank(line))
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])(?:str\s*\(\s*)?([A-Za-z_]\w*)\s*\)?`, _sw]), line, -1)
	v := m[1]
	_canonical_var(lines, i, v)
	_unsafe_arg(m[2], content)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_canonical_var(lines, i, v) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	a := regex.find_all_string_submatch_n(concat("", [`^\s*`, v, `\s*=\s*(.*)$`]), lines[j], 1)
	count(a) > 0
	regex.match(_canon_rhs, a[0][1])
}
