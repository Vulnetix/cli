package vulnetix.rules.vnx_node_017

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-017",
	"name": "Deserialization of untrusted data via node-serialize or serialize-to-js",
	"description": "A value that is not a constant is passed to unserialize() from node-serialize or deserialize() from serialize-to-js. Both libraries evaluate JavaScript embedded in the payload (node-serialize runs an _$$ND_FUNC$$_ IIFE, CVE-2017-5941; serialize-to-js before 2.0 evaluates the string), so whoever controls the input runs code in the server. Reported: a call through a name bound to either module (require, default or namespace import, import = require), a call of an unserialize/deserialize function imported from it by name (including an `as` alias), and require('node-serialize').unserialize(...) inline, in JavaScript and TypeScript files, with the argument on the same line or the next. Not reported: serialize() (the writing side), a string-literal argument, deserialize()/unserialize() from any other library (bson, avsc, php-serialize) or a class method of that name, and comments or string literals that mention the call. Use JSON.parse() for untrusted data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-017/",
	"languages": ["javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["deserialization", "rce", "node-serialize", "node"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_mod := `['"](?:node-serialize|serialize-to-js)['"]`

# Names bound to the whole module.
_alias_res := [
	concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*`, _mod, `\s*\)`]),
	concat("", [`\bimport\s+(?:\*\s+as\s+)?(\w+)\s+from\s+`, _mod]),
	concat("", [`\bimport\s+(\w+)\s*=\s*require\(\s*`, _mod]),
]

# Brace lists of names imported from the module.
_named_res := [
	concat("", [`\bimport\s*\{([^}]*)\}\s*from\s*`, _mod]),
	concat("", [`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*`, _mod]),
]

# A string literal's content is not code.
_strip(line) := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, `""`)

_aliases(lines) := {a |
	some l in lines
	contains(l, "serialize")
	not helpers.is_comment_line(l)
	some re in _alias_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	a := m[1]
}

_named(lines) := {local |
	some l in lines
	contains(l, "serialize")
	not helpers.is_comment_line(l)
	some re in _named_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	some item in split(m[1], ",")
	parts := regex.split(`\s+as\s+|\s*:\s*`, trim_space(item))
	parts[0] in {"unserialize", "deserialize"}
	local := trim_space(parts[count(parts) - 1])
}

# The sink expression on a code line, capturing what follows the paren.
_sink_res(aliases, named) := array.concat(
	[concat("", [`\b`, a, `\s*\.\s*(?:unserialize|deserialize)\s*\((.*)$`]) | some a in aliases],
	[concat("", [`(?:^|[^.\w])`, n, `\s*\((.*)$`]) | some n in named],
)

_inline_re := concat("", [`require\(\s*`, _mod, `\s*\)\s*\.\s*(?:unserialize|deserialize)\s*\((.*)$`])

# The text after each sink paren on the line, string literals stripped.
_sink_rests(line, res) := {r |
	some re in res
	some m in regex.find_all_string_submatch_n(re, _strip(line), 1)
	r := m[1]
} | {r |
	some m in regex.find_all_string_submatch_n(_inline_re, line, 1)
	r := _strip(m[1])
}

# The argument is a lone string literal (checked on the raw line, since the
# stripped line no longer shows it).
_constant_arg(rest) if regex.match(`^\s*""\s*[,)]`, rest)

_constant_arg(rest) if regex.match(`^\s*\)`, rest)

_arg_text(lines, i, rest) := rest if trim_space(rest) != ""

_arg_text(lines, i, rest) := _strip(lines[j]) if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(`node-serialize|serialize-to-js`, content)
	regex.match(`(?:unserialize|deserialize)`, content)
	lines := split(content, "\n")
	aliases := _aliases(lines)
	named := _named(lines)
	res := _sink_res(aliases, named)
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:async\s+)?(?:function\s+)?(?:unserialize|deserialize)\s*\([^)]*\)\s*\{`, line)
	some rest in _sink_rests(line, res)
	not _constant_arg(_arg_text(lines, i, rest))
	finding := {
		"rule_id": metadata.id,
		"message": "node-serialize unserialize() / serialize-to-js deserialize() evaluates JavaScript embedded in its input; an attacker who controls this value runs code on the server. Use JSON.parse() instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
