# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_824

import rego.v1


metadata := {
	"id": "VNX-824",
	"name": "Access of Uninitialized Pointer",
	"description": "Reports a C or C++ local pointer declared without an initialiser (char *p; struct node *n; std::string *s;) whose first mention in the same function, within 40 lines, dereferences it before anything stores an address in it: *p, p->field, p[i], a destination or source argument of strcpy/strncpy/strcat/memcpy/memmove/memset/sprintf/snprintf/fgets/gets/read/recv/fread/strlen/strcmp/printf/puts/free, or delete p. The pointer holds whatever was on the stack, so the access reads or writes an arbitrary address. Not reported: a first mention that assigns it (p = malloc(...), for (p = head; ...), if ((p = f()) == NULL)), takes its address (getaddrinfo(..., &res), getline(&line, ...)), or only tests it; pointers with an initialiser, static, extern and file-scope pointers (zero-initialised), struct, union and class members, K&R parameter declarations, a line that continues an expression from the line above (rate * count;), declarations listing several pointers, uses after the first mention, flow through other functions, comments and string literals. Uninitialised scalars and arrays are VNX-457.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-824/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [824],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["access-of-uninitialized-pointer", "cwe-824", "c", "cpp", "memory-safety"],
}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$))`, line)

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_decl_re := `^\s+(?:(?:const|volatile|unsigned|signed|struct|enum|union|register|class)\s+)*([A-Za-z_][\w:]*(?:<[^;=()]*>)?)\s*(?:\*\s*(?:const\s*)?)+([A-Za-z_]\w*)\s*;\s*(?://.*|/\*.*)?$`

_not_types := {"return", "delete", "throw", "case", "goto", "else", "sizeof", "typedef", "do", "co_return"}

# Strings, trailing comments and sizeof operands (never evaluated) removed.
_strip(line) := regex.replace(
	regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/`, ""),
	`\bsizeof\s*(?:\((?:[^()]|\([^()]*\))*\)|\s+\**\s*\w+)`, "0",
)

# The mention is a new declaration of the same name in an inner scope.
_redeclares(code, v) if regex.match(concat("", [`^\s*(?:(?:const|static|struct|unsigned|signed|volatile|enum|union|class)\s+)*[A-Za-z_][\w:]*(?:<[^;=()]*>)?\s*\*+\s*`, v, `\s*(?:=|;|,|\[|\))`]), code)

# A nested struct or union closed between the declaration and the mention:
# the declaration was one of its members.
_nested_member(lines, i, k) if {
	i + 1 <= k - 1
	some j in numbers.range(i + 1, k - 1)
	regex.match(`^\s+}\s*[\w\[]`, lines[j])
}

# A member declaration: the enclosing column-0 construct is a type body, or
# an access label sits just above.
_member(lines, starts, i) if {
	s := max(array.concat([0], [j | some j in starts; j < i]))
	regex.match(`^(?:typedef\s+)?(?:class|struct|union)\b[^()]*$`, lines[s])
}

_member(lines, _, i) if {
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(`^\s*(?:public|private|protected)\s*:|^\s+(?:class|struct|union)\s+\w+[^;()]*$`, lines[j])
}

_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 40])
	ends := [k | some k in numbers.range(i + 1, last); startswith(lines[k], "}")]
	e := min(array.concat([last], ends))
}

# A mention of v that is not a member of something else (x.v, x->v, X::v).
_mentions(code, v) if regex.match(concat("", [`(?:^|[^\w.>:])`, v, `\b`]), code)

_deref(code, v) if regex.match(concat("", [`(?:^|[^\w)\]])\*\s*`, v, `\b`]), code)

_deref(code, v) if regex.match(concat("", [`(?:^|[^\w.>:])`, v, `\s*(?:->|\[)`]), code)

_deref(code, v) if regex.match(concat("", [`\b(?:strcpy|strncpy|strcat|strncat|memcpy|memmove|memset|sprintf|snprintf|vsprintf|fgets|gets|read|recv|fread|strlen|strcmp|strncmp|printf|puts|free)\s*\((?:[^()]*,)?\s*`, v, `\s*[,)]`]), code)

_deref(code, v) if regex.match(concat("", [`\bdelete\s*(?:\[\s*\])?\s*`, v, `\b`]), code)

_initialises(code, v) if regex.match(concat("", [`(?:^|[^\w.>:*&])`, v, `\s*=[^=]`]), code)

_initialises(code, v) if regex.match(concat("", [`&\s*`, v, `\b`]), code)

# The line continues an expression from the line above (rate * count;) or
# follows a K&R function header, so it is not a declaration statement.
_continuation(lines, i) if {
	i > 0
	js := [j | some j in numbers.range(max([0, i - 6]), i - 1); trim_space(lines[j]) != ""; not _is_comment(lines[j])]
	count(js) > 0
	t := trim_space(_strip(lines[js[count(js) - 1]]))
	t != ""
	not regex.match(`(?:[;{}:]|\*/|\\)$|^#`, t)
}

# A K&R parameter declaration: the function body opens after it.
_knr_param(lines, i, k) if {
	i + 1 <= k - 1
	some j in numbers.range(i + 1, k - 1)
	startswith(lines[j], "{")
}

findings contains finding if {
	some path, content in input.file_contents
	some x in _exts
	endswith(path, x)
	regex.match(`(?m)^\s+[\w:<> ]+\*\s*[A-Za-z_]\w*\s*;`, content)
	not regex.match(`(?m)^\s*@(?:interface|implementation|protocol)\b`, content)
	lines := split(content, "\n")
	starts := [j | some j, l in lines; regex.match(`^[A-Za-z_]`, l)]
	some i, line in lines
	contains(line, "*")
	contains(line, ";")
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(m) > 0
	not m[0][1] in _not_types
	v := m[0][2]
	not _member(lines, starts, i)
	e := _end(lines, i)
	firsts := [k |
		some k in numbers.range(i + 1, e)
		not _is_comment(lines[k])
		_mentions(_strip(lines[k]), v)
	]
	count(firsts) > 0
	k := firsts[0]
	code := _strip(lines[k])
	not _redeclares(code, v)
	not _nested_member(lines, i, k)
	not _knr_param(lines, i, k)
	not _continuation(lines, i)
	not _initialises(code, v)
	_deref(code, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("pointer '%s' is declared without an initialiser and dereferenced before anything is stored in it: it points at whatever address was left on the stack. Initialise it (to NULL or a valid object) where it is declared", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}
