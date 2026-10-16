# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_636

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-636",
	"name": "Not Failing Securely ('Failing Open')",
	"description": "A security decision that grants access when it fails: inside a function or method whose name says it decides access (auth, permission, access, allow, privilege, admin, verify, signature, token, csrf, trust, acl, policy, role, guard, session, credential, grant, entitle, canX/can_x), an exception handler (Python except, Java/JavaScript/TypeScript catch) whose body returns True/true, or calls next() with no error in JavaScript middleware, or a promise .catch() handler that resolves to true (.catch(() => true)),or swallows the exception (pass, an empty catch block) and falls through to return True/true. A policy engine timeout, a malformed token or a bad signature then reads as allowed. Not reported: handlers that return False, raise, rethrow, respond 401/403 or pass the error to next(err); the same shapes in functions whose names are not about access (fileExists, isCached, isNumeric); test code; comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-636/",
	"languages": ["java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [636],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["fail-open", "exception-handling", "authorization", "cwe-636"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_blank(line) if trim_space(line) == ""

# ── Enclosing function name ──────────────────────────────────────────────

_decl_res := {
	"py": [`^\s*(?:async\s+)?def\s+(\w+)\s*\(`],
	"java": [`^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|synchronized|abstract|default)\s+)*[\w<>\[\]?,. ]+\s+(\w+)\s*\([^;=]*$`],
	"js": [
		`\bfunction\s*\*?\s*(\w+)\s*\(`,
		`^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|\w+\s*=>)`,
		`^\s*(?:(?:public|private|protected|static|async|override)\s+)*(\w+)\s*\([^;=]*\)\s*(?::\s*[^={;]+)?\{\s*$`,
		`^\s*(\w+)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)`,
	],
}

_keywords := {"if", "for", "while", "switch", "catch", "synchronized", "return", "else", "try", "do", "new", "throw", "with", "function"}

_decl_name(lang, line) := n if {
	some re in _decl_res[lang]
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	n := m[0][1]
	not n in _keywords
}

_enclosing(lang, lines, i) := name if {
	ii := _indent(lines[i])
	cands := [j |
		some j in numbers.range(max([0, i - 80]), i - 1)
		_indent(lines[j]) < ii
		_decl_name(lang, lines[j])
	]
	count(cands) > 0
	name := _decl_name(lang, lines[max(cands)])
}

_security_name(n) if regex.match(`(?i)(auth|permi|access|allow|privileg|admin|verif|signature|token|csrf|xsrf|trust|acl|polic|role|guard|canactivate|login|session|credential|entitle|grant)`, n)

_security_name(n) if regex.match(`^can[A-Z_]`, n)

# ── Handler bodies ───────────────────────────────────────────────────────

# Body lines of the handler opened at line i: deeper than i, with nothing at
# i's level or shallower between.
_body_line(lines, i, j) if {
	ii := _indent(lines[i])
	not _blank(lines[j])
	_indent(lines[j]) > ii
	not _left_block(lines, i, j, ii)
}

_left_block(lines, i, j, ii) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	not _blank(lines[k])
	_indent(lines[k]) <= ii
}

_true_return("py", l) if regex.match(`^\s*return\s+True\s*(#.*)?$`, l)

_true_return(lang, l) if {
	lang != "py"
	regex.match(`^\s*return\s+true\s*;?\s*(//.*)?$`, l)
}

_handler("py", line) if regex.match(`^\s*except\b[^:]*:`, line)

_handler(lang, line) if {
	lang != "py"
	regex.match(`\bcatch\b\s*(\([^)]*\))?\s*\{`, line)
}

# One-line handler: `except E: return True`, `catch (e) { return true; }`.
_fail_open("py", lines, i, i) if regex.match(`^\s*except\b[^:]*:\s*return\s+True\s*(#.*)?$`, lines[i])

_fail_open(lang, lines, i, i) if {
	lang != "py"
	regex.match(`\bcatch\b\s*(\([^)]*\))?\s*\{\s*return\s+true\s*;?\s*\}`, lines[i])
}

# The handler body returns true (or calls next() with no error).
_fail_open(lang, lines, i, j) if {
	j > i
	j <= i + 5
	_true_return(lang, lines[j])
	_body_line(lines, i, j)
}

_fail_open("js", lines, i, j) if {
	j > i
	j <= i + 5
	regex.match(`^\s*(return\s+)?next\(\s*\)\s*;?\s*$`, lines[j])
	_body_line(lines, i, j)
}

# A promise rejection handler that resolves to true: .catch(() => true).
_promise_catch_true := `\.catch\(\s*(?:async\s+)?(?:\(\s*[\w$]*\s*(?::\s*\w+\s*)?\)|[\w$]+)\s*=>\s*(?:true|\{\s*return\s+true\s*;?\s*\})\s*\)`

_handler("js", line) if regex.match(_promise_catch_true, line)

_fail_open("js", lines, i, i) if regex.match(_promise_catch_true, lines[i])

# The exception is swallowed and the function falls through to return true.
_fail_open("py", lines, i, r) if {
	_true_return("py", lines[r])
	b := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*pass\s*$`, lines[b])
	_indent(lines[b]) > _indent(lines[i])
	r == helpers.next_code_index(lines, b, 3)
	_indent(lines[r]) <= _indent(lines[i])
}

_fail_open(lang, lines, i, r) if {
	lang != "py"
	_true_return(lang, lines[r])
	some c in _empty_catch(lines, i)
	r == helpers.next_code_index(lines, c, 3)
}

_empty_catch(lines, i) := {c |
	regex.match(`\bcatch\b\s*(\([^)]*\))?\s*\{\s*\}\s*$`, lines[i])
	c := i
} | {c |
	regex.match(`\bcatch\b\s*(\([^)]*\))?\s*\{\s*$`, lines[i])
	c := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*\}\s*$`, lines[c])
}

_gate := {
	"py": `except`,
	"java": `catch`,
	"js": `catch`,
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _gate[lang])
	regex.match(`(?i)return\s+true|next\(\s*\)|=>\s*true`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _gate[lang])
	_handler(lang, line)
	some r in numbers.range(i, min([count(lines) - 1, i + 8]))
	_fail_open(lang, lines, i, r)
	name := _enclosing(lang, lines, i)
	_security_name(name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Access check %s fails open: when it raises, the handler grants access. Deny on error (return false, rethrow, or respond 401/403)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r + 1,
		"snippet": lines[r],
	}
}
