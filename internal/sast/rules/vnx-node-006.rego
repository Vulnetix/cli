package vulnetix.rules.vnx_node_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-006",
	"name": "Prototype pollution via merge",
	"description": "A deep-merge or path-assignment function is given request data: lodash _.merge/mergeWith/defaultsDeep/set/setWith/zipObjectDeep/update/updateWith (as _., lodash. or a destructured or default import of lodash, lodash.merge, deepmerge, merge-deep, mixin-deep, deep-extend, set-value or dset), jQuery $.extend(true, ...), and objectPath.set/dotProp.set, where an argument is req.body/query/params/cookies/headers, the parsed body of a fetch-style request (await request.json() or formData()), ctx.request.body, ctx.query, event.body or location.hash/search, directly or through a variable assigned from one in the previous 15 lines (arguments spanning up to 5 lines are read). A __proto__ or constructor key then writes Object.prototype, which leads to denial of service, authorization bypass or code execution. Not reported: merges of constants or configuration files, Object.assign and spread (shallow copies do not reach the prototype), arguments filtered through pick(), code that checks for __proto__/constructor keys in the 10 lines before the call, read-only _.get, and merge methods on other objects (Immutable, wysihtml). Hand-written recursive merge functions are not analysed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-006/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-180"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["prototype-pollution", "lodash", "injection"],
}

_is_js(path) if regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$`, path)

_file_gate := `(?:\b_|lodash|\$|jQuery|objectPath|dotProp)\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep|update|updateWith|extend)\s*\(|['"](?:lodash[\w./-]*|deepmerge|merge-deep|mixin-deep|deep-extend|set-value|dset)['"]`

_merge_modules := `['"](?:lodash(?:-es)?(?:[./][\w.]+)?|deepmerge|merge-deep|mixin-deep|deep-extend|set-value|dset)['"]`

_member_sinks := [
	`(?:^|[^\w$.])(?:_|lodash|[\w$]*[lL]odash[\w$]*)\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep|update|updateWith)\s*\((.*)$`,
	`(?:^|[^\w$.])(?:\$|jQuery)\.extend\s*\(\s*true\s*,(.*)$`,
	`(?:^|[^\w$.])(?:objectPath|dotProp)\.set\s*\((.*)$`,
]

_bare_sink := `(?:^|[^\w$.])(?:merge|mergeWith|defaultsDeep|deepmerge|deepMerge|mergeDeep|deepExtend|mixinDeep|setValue|setWith|dset|zipObjectDeep)\s*\((.*)$`

_source_re := `\b(?:req|request)\.(?:json|formData)\s*\(|\breq\.(?:body|query|params|cookies|headers)|\brequest\.(?:body|query|payload)|\bctx\.(?:request\.body|query|params)|\bevent\.body|\blocation\.(?:hash|search)`

# String literals (without interpolation) collapse to "".
_strip(line) := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\x60[^\x60$]*\x60`, `""`)

_sinks(content) := array.concat(_member_sinks, [_bare_sink | regex.match(_merge_modules, content)])

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	sinks := _sinks(content)
	some i, line in lines
	count(line) <= 400
	regex.match(`(?i)merge|defaults|set|extend|update|zipObject|mixin`, line)
	not helpers.is_comment_line(line)
	s := _strip(line)
	not regex.match(`^\s*(?:export\s+)?(?:async\s+)?function\b`, s)
	some re in sinks
	m := regex.find_all_string_submatch_n(re, s, 1)
	count(m) > 0
	args := _args(lines, i, m[0][1])
	not regex.match(`\bpick(?:By)?\s*\(`, args)
	not _constant_path(m[0][0], args)
	_tainted(lines, i, args)
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Deep merge / path assignment with request data can write __proto__ or constructor.prototype (prototype pollution); validate the keys, merge into Object.create(null), or copy only allow-listed fields",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The call's arguments: the rest of the line, continued to the first line
# that closes a parenthesis when the call spans lines (at most 5).
_args(lines, i, rest) := rest if contains(rest, ")")

_args(lines, i, rest) := concat("\n", array.concat([rest], [_strip(l) | some l in array.slice(lines, i + 1, end + 1)])) if {
	not contains(rest, ")")
	closers := [k | some k in numbers.range(i + 1, min([i + 5, count(lines) - 1])); contains(lines[k], ")")]
	end := min(array.concat([min([i + 5, count(lines) - 1])], closers))
}

# A path-assignment call (set, setWith, update, updateWith, set-value, dset)
# whose path is a string literal or an array of literals writes only that
# path: request data as the value cannot reach the prototype.
_constant_path(call, args) if {
	regex.match(`^[^\w$]?(?:[\w$]+\.)?(?:set|setWith|update|updateWith|setValue|dset)\s*\(`, call)
	regex.match(`^\s*[^,]+,\s*(?:""|\[\s*""(?:\s*,\s*"")*\s*\])\s*[,)]`, args)
}

_tainted(_, _, args) if regex.match(_source_re, args)

_tainted(lines, i, args) if {
	stripped := [_strip(l) | some l in array.slice(lines, max([0, i - 15]), i)]
	some v in helpers.tainted_names(stripped, count(stripped), 15, _source_re)
	regex.match(concat("", [`(?:^|[^\w$.])`, v, `\b`]), args)
}

_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 10, 0)
	regex.match(`__proto__|['"]constructor['"]|['"]prototype['"]`, w)
}
