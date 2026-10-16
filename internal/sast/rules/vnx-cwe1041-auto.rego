# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1041

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1041",
	"name": "Use of Redundant Code",
	"description": "Code that repeats a check it has just made, the copy-paste shape that leaves one copy updated and the other stale, or a branch that can never run. Reported in Go, Java, JavaScript/TypeScript, PHP, Python and Ruby: an else if / elseif / elif / elsif whose condition repeats, character for character, a condition earlier in the same if chain, with braces on the same line or Allman-style (that branch is dead: the earlier branch always wins); a condition joined by && / || / and / or whose two adjacent operands are the same expression (user.isAdmin() || user.isAdmin()); and a security check statement (a call named check..., verify..., validate..., require..., ensure..., enforce..., authorize/authorise..., authenticate..., protect..., guard...) repeated identically on the next code line. Not reported: the same condition in a separate if statement or a nested chain, operands that differ only in an argument, operands that read or draw a new value each time they run (in.read() == 0 && in.read() == 0, next(it), random()), a check called twice with different arguments, checks passed as arguments (route middleware lists), conditions spanning lines, redundancy across functions or files, minified JavaScript, test code, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1041/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1041],
	"capec": ["CAPEC-204"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["redundant-code", "duplicate-check", "dead-branch", "code-quality", "cwe-1041"],
}

# ── Languages ────────────────────────────────────────────────────────────

_lang(path) := "c" if {
	some ext in {".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".php"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "rb" if endswith(path, ".rb")

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/(test|it)/|Test\.php$|_test\.php$`, path)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_blank_line(line) if trim_space(line) == ""

_skippable(line) if _blank_line(line)

_skippable(line) if helpers.is_comment_line(line)

_norm(s) := regex.replace(s, `\s+`, "")

# ── Shape 1: an else-if that repeats a condition of its own chain ────────

_else_re := {
	"c": `^\s*(?:\}\s*)?(?:else\s*if|elseif)\s*\((.*)\)\s*[{:]?\s*$`,
	"go": `^\s*\}\s*else\s+if\s+(.+?)\s*\{\s*$`,
	"py": `^\s*elif\s+(.+?)\s*:\s*$`,
	"rb": `^\s*elsif\s+(.+?)(?:\s+then)?\s*$`,
}

_member_re := {
	"c": `^\s*(?:\}\s*)?(?:else\s*if|elseif|if)\s*\((.*)\)\s*[{:]?\s*$`,
	"go": `^\s*(?:\}\s*else\s+)?if\s+(.+?)\s*\{\s*$`,
	"py": `^\s*(?:el)?if\s+(.+?)\s*:\s*$`,
	"rb": `^\s*(?:els)?if\s+(.+?)(?:\s+then)?\s*$`,
}

# A same-indent line that keeps the chain open.
_cont_re := {
	"c": `^\s*(?:\}\s*)?else(?:if)?\b`,
	"go": `^\s*\}\s*else\b`,
	"py": `^\s*elif\b`,
	"rb": `^\s*elsif\b`,
}

_else_needles := {
	"c": {"else if", "elseif", "else  if"},
	"go": {"else if"},
	"py": {"elif "},
	"rb": {"elsif "},
}

_cond(re, line) := _norm(m[1]) if {
	some m in regex.find_all_string_submatch_n(re, line, 1)
}

_chain_open(lines, j, k, ind, lang) if {
	every m in helpers.span(j + 1, k - 1) {
		_inside_chain(lines[m], ind, lang)
	}
}

_inside_chain(line, _, _) if _skippable(line)

_inside_chain(line, ind, _) if _indent(line) > ind

_inside_chain(line, ind, lang) if {
	_indent(line) == ind
	regex.match(_cont_re[lang], line)
}

# Allman braces: a brace alone on a line at the chain's indent.
_inside_chain(line, ind, "c") if {
	_indent(line) == ind
	trim_space(line) in {"{", "}"}
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	some n in _else_needles[lang]
	contains(content, n)
	not _is_test(path)
	lines := split(content, "\n")
	parts := split(content, n)
	nl := [count(indexof_n(x, "\n")) | some x in parts]
	some p in numbers.range(0, count(parts) - 2)
	k := sum(array.slice(nl, 0, p + 1))
	line := lines[k]
	c := _cond(_else_re[lang], line)
	regex.match(`[A-Za-z_$]`, c)
	ind := _indent(line)
	some j in numbers.range(max([0, k - 60]), k - 1)
	_indent(lines[j]) == ind
	_cond(_member_re[lang], lines[j]) == c
	_chain_open(lines, j, k, ind, lang)
	finding := _finding(path, k, line, "This else-if repeats a condition already tested earlier in the same if chain, so its branch can never run; one copy was probably meant to test something else. Fix or remove the duplicated condition")
}

# ── Shape 2: the same operand on both sides of && / || / and / or ────────

_op := `!?\s*[\w$@.>:\[\]-]+(?:\([^()]*\))?(?:\.[\w$]+(?:\([^()]*\))?)*[?!]?(?:\s*(?:===?|!==?|<=?|>=?|\bis\s+not\b|\bis\b|\bin\b)\s*[\w$@."'\[\]:-]+(?:\([^()]*\))?)?`

_trail_re := concat("", [`(?:^|[(,?:!{]|\b(?:if|while|return|elif|elsif|unless|and|or|not)\b|[^=!<>]=)\s*(`, _op, `)\s*$`])

_lead_re := concat("", [`^\s*(`, _op, `)\s*(?:$|[)?:;{,]|\b(?:then|do)\b)`])

_bool_needles := {
	"c": {"&&", "||"},
	"go": {"&&", "||"},
	"py": {" and ", " or "},
	"rb": {"&&", "||", " and ", " or "},
}

_lits(s) := [m[0] | some m in regex.find_all_string_submatch_n("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`[^`]*`", s, -1)]

_strip_strings(line) :=regex.replace(line, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`[^`]*`", "S")

# The file is split on the operator itself, not into lines, so only the
# text either side of each && / || is examined; the line is looked up
# only for a pair whose operands match.
_last_line(s) := ls[count(ls) - 1] if ls := split(s, "\n")

_first_line(s) := substring(s, 0, i) if {
	i := indexof(s, "\n")
	i >= 0
}

_first_line(s) := s if indexof(s, "\n") < 0

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	some opn in _bool_needles[lang]
	contains(content, opn)
	not _is_test(path)
	parts := split(content, opn)
	some p in numbers.range(0, count(parts) - 2)
	b0 := _first_line(parts[p + 1])
	some w in regex.find_n(`^\s*!?\s*[\w$@]+`, b0, 1)
	contains(_last_line(parts[p]), trim_left(trim_space(w), "!"))
	some a in regex.find_all_string_submatch_n(_trail_re, _last_line(parts[p]), 1)
	some b in regex.find_all_string_submatch_n(_lead_re, _first_line(parts[p + 1]), 1)
	x := trim_right(_norm(a[1]), ":")
	x == trim_right(_norm(b[1]), ":")
	# _norm drops whitespace inside string literals too, so "extra ==" and
	# "extra==" would compare equal; the literals must match exactly.
	_lits(a[1]) == _lits(b[1])
	not regex.match(_consuming, x)
	regex.match(`[A-Za-z_]`, x)
	not x in {"true", "false", "null", "nil", "None", "True", "False", "undefined"}
	k := count(indexof_n(concat(opn, array.slice(parts, 0, p + 1)), "\n"))
	lines := split(content, "\n")
	line := lines[k]
	not helpers.is_comment_line(line)
	count(line) < 400
	count({n | some n in _bool_needles[lang]; contains(_strip_strings(line), n)}) == 1
	not _continues(lines, k)
	finding := _finding(path, k, line, "Both operands of this && / || are the same expression, so the second test is redundant; it was probably meant to test something else. Fix or remove the duplicated operand")
}

# A call that consumes input or draws a new value each time it runs: the
# same text on both sides of the operator tests two different values.
_consuming := `(?i)(?:^|[.>:!])(?:read\w*|next\w*|get|pop|shift|poll|take|scan\w*|getc|fgetc|getchar|rand\w*|random\w*|uuid\w*)\(`

# ── Shape 3: a security check repeated on the next code line ─────────────

_check_name := `(?:^|[._>:\s$])(?:check|verify|validate|require|ensure|enforce|authori[sz]e|authenticate|protect|guard|Check|Verify|Validate|Require|Ensure|Enforce|Authori[sz]e|Authenticate|Protect|Guard)\w*[!?]?\s*(?:\(.*\)|\s+[^=\s].*)\s*;?\s*$`

_stmt_re := `^\s*(?:await\s+)?[\w$](?:[\w$.]|->|::|&\.)*[!?]?\s*(?:\(.*\)|\s+[^=\s].*)\s*;?\s*$`

_check_needles := {
	"check", "verify", "validate", "require", "ensure", "enforce", "authori", "authenticate", "protect", "guard",
	"Check", "Verify", "Validate", "Require", "Ensure", "Enforce", "Authori", "Authenticate", "Protect", "Guard",
}

_has_check(s) if {
	some n in _check_needles
	contains(s, n)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	_has_check(content)
	_dup_check_tail(content)
	not _is_test(path)
	lines := split(content, "\n")
	some k, line in lines
	k > 0
	line == lines[k - 1]
	t := trim_space(line)
	t != ""
	_has_check(t)
	not helpers.is_comment_line(line)
	not endswith(t, ",")
	not endswith(t, "{")
	not endswith(t, "(")
	regex.match(_stmt_re, t)
	regex.match(_check_name, t)
	finding := _finding(path, k, line, "This security check repeats the statement on the line above, a copy-paste duplicate; if one copy is later changed the two will disagree. Remove the duplicate or fix the copy that was meant to check something else")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A JavaScript chain that continues on the next line (`$p && $p\n  .find()`)
# makes the last operand longer than the line shows.
_continues(lines, k) if {
	k + 1 < count(lines)
	t := trim_space(lines[k + 1])
	some p in {".", "?.", "->", "(", "[", "+", "-", "*", "/", "&&", "||", "and ", "or "}
	startswith(t, p)
}

# Two identical lines carry identical text from the check name to the end
# of the line, so a file in which no such tail occurs twice is never split.
# Each expression starts with a literal and is found by substring search.
_dup_check_tail(content) if {
	some n in _check_needles
	contains(content, n)
	ms := regex.find_all_string_submatch_n(concat("", [n, `[^\n]*`]), content, -1)
	count(ms) > count({m[0] | some m in ms})
}
