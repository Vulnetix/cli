# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_41

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-41",
	"name": "Improper Resolution of Path Equivalence",
	"description": "A directory-containment check (startsWith/startswith/is_relative_to/strings.HasPrefix against a base directory) is made on a path that was never canonicalised, so an equivalent spelling of an outside path (base/../etc/passwd, a doubled separator) passes the check. Reported: Java File.getAbsolutePath()/getAbsoluteFile()/getPath(), Path.resolve()/Paths.get()/Path.of()/toAbsolutePath() checked with startsWith, inline or through a variable assigned in the 15 lines above; Python os.path.join() or string concatenation checked with startswith, and a pathlib path checked with is_relative_to without resolve(); JavaScript/TypeScript paths built by concatenation or a template literal from a base directory and checked with startsWith; Go paths built by concatenation or fmt.Sprintf checked with strings.HasPrefix. Not reported: paths canonicalised before the check (getCanonicalPath, normalize(), toRealPath, os.path.realpath/abspath/normpath, Path.resolve(), path.resolve/normalize/join, fs.realpath, filepath.Join/Clean/Abs/EvalSymlinks, path.Join/Clean), including a later reassignment of the variable to its canonical form, prefix checks against a non-path literal such as \"https://\", and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-41/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [41],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["path-equivalence", "traversal", "cwe-41"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_check_needle := {"go": "HasPrefix(", "py": "", "java": "startsWith(", "js": "startsWith("}

_has_check(line, "py") if contains(line, ".startswith(")

_has_check(line, "py") if contains(line, ".is_relative_to(")

_has_check(line, lang) if {
	lang != "py"
	contains(line, _check_needle[lang])
}

# receiver, argument of the containment check
_check_re := {
	"java": `\b(\w+)\s*\.\s*startsWith\s*\(\s*([^)]*)`,
	"js": `\b(\w+)\s*\.\s*startsWith\s*\(\s*([^)]*)`,
	"py": `\b(?:str\(\s*)?(\w+)\s*\)?\s*\.\s*(?:startswith|is_relative_to)\s*\(\s*([^)]*)`,
	"go": `\bstrings\.HasPrefix\s*\(\s*(\w+)\s*,\s*([^)]*)`,
}

# The check made directly on a non-canonical expression.
_inline_re := {
	"java": `(getAbsolutePath\(\)|getAbsoluteFile\(\)|getPath\(\)|toAbsolutePath\(\)|\.resolve\s*\([^()]*\))\s*\.\s*startsWith\s*\(`,
	"py": `\bos\.path\.join\s*\([^()]*\)\s*\.\s*startswith\s*\(`,
	"js": `^$`,
	"go": `^$`,
}

# Expressions that build a path without resolving `..`.
_producer := {
	"java": `getAbsolutePath\(\)|getAbsoluteFile\(\)|\.getPath\(\)|\.resolve\s*\(|\bPaths\.get\s*\(|\bPath\.of\s*\(|toAbsolutePath\(\)`,
	"py": `\bos\.path\.join\s*\(|\w\s*/\s*\w|\+`,
	"js": `\+|\$\{`,
	"go": `\+|\bfmt\.Sprintf\s*\(`,
}

_canonical := {
	"java": `getCanonical|\bnormalize\s*\(\s*\)|toRealPath`,
	"py": `\b(realpath|abspath|normpath)\s*\(|\.resolve\s*\(`,
	"js": `\bpath\.(resolve|normalize|join)\s*\(|realpath|\bresolve\s*\(`,
	"go": `\bfilepath\.(Join|Clean|Abs|EvalSymlinks)\s*\(|\bpath\.(Join|Clean)\s*\(`,
}

# A concatenation only counts when it is building a path under a directory.
_dirish := `(?i)(dir|root|base|upload|public|static|folder|storage|__dirname)`

_needs_dirish := {"py", "js", "go"}

# The prefix compared against is a directory: an expression, or a literal
# that starts like an absolute path. `url.startsWith("https://")` is not one.
_path_arg(arg) if not regex.match(`^\s*["'\x60]`, arg)

# (a bare "/" asks whether the path is absolute, not where it is)
_path_arg(arg) if regex.match(`^\s*["'\x60](/[^"'\x60\s]+|[A-Za-z]:\\\\)`, arg)

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Directory containment is checked on a path that was never canonicalised, so an equivalent spelling such as base/../../etc/passwd still starts with the base directory and passes. Canonicalise first (getCanonicalPath/normalize/toRealPath, os.path.realpath, Path.resolve, path.resolve, filepath.Clean) and compare against the canonical base followed by a separator",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_check(content, lang)
	lines := split(content, "\n")
	some i, line in lines
	_has_check(line, lang)
	not helpers.is_comment_line(line)
	_unresolved(lang, lines, i, line)
	finding := _finding(path, i, line)
}

_unresolved(lang, _, _, line) if {
	regex.match(_inline_re[lang], line)
	not regex.match(_canonical[lang], line)
}

_unresolved(lang, lines, i, line) if {
	some m in regex.find_all_string_submatch_n(_check_re[lang], line, -1)
	recv := m[1]
	_path_arg(m[2])
	j := _last_assignment(lines, i, recv)
	rhs := lines[j]
	regex.match(_producer[lang], rhs)
	not regex.match(_canonical[lang], rhs)
	_dirish_ok(lang, rhs, m[2])
}

_dirish_ok(lang, _, _) if not lang in _needs_dirish

_dirish_ok(lang, rhs, arg) if {
	lang in _needs_dirish
	regex.match(_dirish, concat(" ", [rhs, arg]))
}

# The most recent assignment to `name` in the 15 lines above i.
_last_assignment(lines, i, name) := j if {
	i > 0
	cands := [k |
		some k in numbers.range(max([0, i - 15]), i - 1)
		contains(lines[k], name)
		not helpers.is_comment_line(lines[k])
		helpers.assigned_first(lines[k]) == name
	]
	count(cands) > 0
	j := max(cands)
}
