package vulnetix.rules.vnx_node_023

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-023",
	"name": "Unsafe YAML.load() with untrusted input",
	"description": "js-yaml parses caller-supplied YAML with a schema that includes the JavaScript types (!!js/function, !!js/regexp, !!js/undefined): in js-yaml 3 load()/loadAll() default to DEFAULT_FULL_SCHEMA, so an uploaded document can plant a function that runs when the application calls or stringifies the value. Reported, in JavaScript and TypeScript files that import or require js-yaml: load()/loadAll() called through a name bound to the module or imported by name (including an `as` alias), with no safe schema in the call, whose argument (on the line or the next two) is an Express/Koa/Lambda request value or an uploaded file buffer (req.body/query/params/file(s), ctx.request, event.body, file.buffer), directly or through a variable assigned from one within the previous 15 lines, including the call written inside a vm.runInContext() script; and load() given DEFAULT_FULL_SCHEMA explicitly with any non-constant input. Not reported: safeLoad()/safeLoadAll(), a call passing JSON_SCHEMA, CORE_SCHEMA, FAILSAFE_SCHEMA or DEFAULT_SAFE_SCHEMA, load() of the program's own files, load() without a schema when the project's package.json depends on js-yaml 4 or later (whose load() is the safe loader), the yaml (eemeli) and yamljs packages, comments and string literals elsewhere.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-023/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["deserialization", "yaml", "js-yaml", "rce", "node"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_mod := `['"]js-yaml['"]`

_alias_res := [
	concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*`, _mod, `\s*\)`]),
	concat("", [`\bimport\s+(?:\*\s+as\s+)?(\w+)\s*(?:,\s*\{[^}]*\}\s*)?from\s+`, _mod]),
	concat("", [`\bimport\s+(\w+)\s*=\s*require\(\s*`, _mod]),
]

_named_res := [
	concat("", [`\bimport\s*(?:\w+\s*,\s*)?\{([^}]*)\}\s*from\s*`, _mod]),
	concat("", [`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*`, _mod]),
]

_source := `\b(?:req|request)\.(?:body|query|params|headers|cookies|files?|rawBody)\b|\bctx\.(?:request|query|params)\b|\bevent\.(?:body|queryStringParameters)\b|\bfile\.buffer\b`

_safe_schema := `\b(?:JSON_SCHEMA|CORE_SCHEMA|FAILSAFE_SCHEMA|DEFAULT_SAFE_SCHEMA)\b`

_strip(line) := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, `""`)

# A script handed to vm is code; elsewhere a string literal is not.
_code(line) := line if regex.match(`\brunIn(?:New|This)?Context\s*\(`, line)

_code(line) := _strip(line) if not regex.match(`\brunIn(?:New|This)?Context\s*\(`, line)

_aliases(lines) := {a |
	some l in lines
	contains(l, "js-yaml")
	not helpers.is_comment_line(l)
	some re in _alias_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	a := m[1]
}

_named(lines) := {local |
	some l in lines
	contains(l, "js-yaml")
	not helpers.is_comment_line(l)
	some re in _named_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	some item in split(m[1], ",")
	parts := regex.split(`\s+as\s+|\s*:\s*`, trim_space(item))
	parts[0] in {"load", "loadAll"}
	local := trim_space(parts[count(parts) - 1])
}

_sink_re(aliases, named) := concat("|", array.concat(
	[concat("", [`\b`, a, `\s*\.\s*load(?:All)?\s*\(`]) | some a in aliases],
	[concat("", [`(?:^|[^.\w])`, n, `\s*\(`]) | some n in named],
))

# The call's argument text: the rest of the line after the sink, and the
# next two lines when the call continues.
_arg(lines, i, code, re) := arg if {
	parts := regex.split(re, code)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	arg := _continued(lines, i, rest)
}

_continued(_, _, rest) := rest if contains(rest, ")")

_continued(lines, i, rest) := concat(" ", array.concat([rest], next)) if {
	not contains(rest, ")")
	next := [_strip(lines[j]) | some j in numbers.range(i + 1, min([i + 2, count(lines) - 1]))]
}

# A request value that only names which of the program's own files to read
# (fs.readFileSync(dir + key)) does not supply the YAML.
_content(arg) := regex.replace(arg, `\b(?:fs\.)?(?:readFileSync|readFile|promises\.readFile)\s*\([^)]*\)`, "")

_reaches(_, _, arg) if regex.match(_source, _content(arg))

_reaches(lines, i, arg) if {
	some v in helpers.tainted_names(lines, i, 15, _source)
	regex.match(concat("", [`\b`, v, `\b`]), _content(arg))
}

# js-yaml 4's load() is the safe loader. A project that declares 4+ (and no
# older js-yaml) is judged on explicit schemas only.
_manifest_v4 if {
	some p, c in input.file_contents
	endswith(p, "package.json")
	regex.match(`"js-yaml"\s*:\s*"[\^~>=v]*[4-9]\.`, c)
}

_manifest_old if {
	some p, c in input.file_contents
	endswith(p, "package.json")
	regex.match(`"js-yaml"\s*:\s*"[\^~>=v]*[0-3]\.`, c)
}

_default_unsafe if not _manifest_v4

_default_unsafe if _manifest_old

_unsafe(lines, i, arg) if {
	_default_unsafe
	not regex.match(_safe_schema, arg)
	not regex.match(`\bschema\s*:`, arg)
	_reaches(lines, i, arg)
}

_unsafe(_, _, arg) if {
	regex.match(`\bDEFAULT_FULL_SCHEMA\b`, arg)
	not regex.match(`^\s*(?:""|\))`, arg)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	contains(content, "js-yaml")
	contains(content, "load")
	lines := split(content, "\n")
	re := _sink_re(_aliases(lines), _named(lines))
	re != ""
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(re, code)
	arg := _arg(lines, i, code, re)
	_unsafe(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "js-yaml load() with the full schema parses !!js/function and other JavaScript types; caller-supplied YAML can plant code. Use safeLoad() (js-yaml 3), upgrade to js-yaml 4, or pass { schema: JSON_SCHEMA }",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
