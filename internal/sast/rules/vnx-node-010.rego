package vulnetix.rules.vnx_node_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-010",
	"name": "Node.js path traversal",
	"description": "A file-system path built from the incoming request: the path (first argument) of an fs/fs.promises/fs-extra call that reads, writes, streams, lists, stats or deletes (readFile, readFileSync, createReadStream, createWriteStream, writeFile, appendFile, unlink, rm, readdir, stat, access, open, copyFile, rename, mkdir, existsSync, outputFile, remove, readJson; also the bare names imported from fs or fs/promises), or of res.sendFile/res.download, is a req/request query, params, body, headers, cookies, url, originalUrl or path value, a Koa ctx.query/ctx.params/ctx.request.body value, or a variable assigned (or destructured) from one in the 25 lines above, directly or through one intermediate assignment such as path.join(dir, name). Not reported: a path passed through path.basename, checked with startsWith against a base directory, checked for '..' or '/', matched against an anchored regex or a sanitize/isValid function in the lines above; res.sendFile/res.download with a root option (send rejects paths that climb out of root); request values written as file data rather than used as the path; constant paths; comments and string literals. Flows through helper functions or across files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-010/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "file-access", "lfi"],
}

_msg := "File path built from request input (path traversal): '../' sequences or an absolute path reach files outside the intended directory. Reduce the name with path.basename, or resolve it and check it stays under the base directory, before opening it"

_is_js(path) if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_src := `\b(?:req|request)\.(?:query|body|params|headers|cookies|url|originalUrl|path|payload)\b|\breq\.(?:param|get|header)\s*\(|\bctx\.(?:request\.)?(?:query|body|params|headers|querystring|path|url)\b`

_fs_ops := `readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|readdir|readdirSync|stat|statSync|lstat|lstatSync|access|accessSync|open|openSync|copyFile|copyFileSync|rename|renameSync|mkdir|mkdirSync|existsSync|outputFile|outputFileSync|remove|removeSync|readJson|readJsonSync`

_member_sink := concat("", [`(?:^|[^\w$])(?:fs|fsp|fsPromises|promises|fse|fsExtra|fs\.promises)\.(?:`, _fs_ops, `)\s*\(`])

_bare_sink := `(?:^|[^\w.$])(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|unlink|rm|readdir|stat|access|open|copyFile|rename|mkdir|existsSync)\s*\(`

_res_sink := `\bres\.(?:sendFile|download)\s*\(`

_imports_fs_names(content) if regex.match(`(?:import\s*\{[^}]*\}\s*from|\{[^}]*\}\s*=\s*require\()\s*['"](?:node:)?fs(?:/promises|-extra)?['"]`, content)

_sinks_for(content) := [_member_sink, _res_sink, _bare_sink] if _imports_fs_names(content)

_sinks_for(content) := [_member_sink, _res_sink] if not _imports_fs_names(content)

# A quoted string holding ${ is the inside of a template literal (`a '${x}'`)
# and is kept, so the interpolation stays visible.
_blank(s) := regex.replace(s, `'(?:[^'\\$]|\\.|\$[^{'])*'|"(?:[^"\\$]|\\.|\$[^{"])*"`, "''")

_opens(s) := count(indexof_n(s, "(")) - count(indexof_n(s, ")"))

# The call's text after its opening parenthesis, continued over at most six
# further lines while its parentheses are open.
_call_text(lines, i, rest) := rest if _opens(rest) < 0

_call_text(lines, i, rest) := t if {
	_opens(rest) >= 0
	last := min([count(lines) - 1, i + 6])
	last >= i + 1
	t := concat(" ", array.concat([rest], array.slice(lines, i + 1, last + 1)))
}

_call_text(lines, i, rest) := rest if {
	_opens(rest) >= 0
	i + 1 > count(lines) - 1
}

# The first top-level argument; strings, template literals and bracketed
# groups (two levels deep) are taken whole.
_arg_re := "^(?:'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`(?:[^`\\\\]|\\\\.)*`|\\((?:[^()]|\\([^()]*\\))*\\)|\\[(?:[^\\[\\]]|\\[[^\\[\\]]*\\])*\\]|\\{(?:[^{}]|\\{[^{}]*\\})*\\}|[^,()\\[\\]{}'\"`])*"

_first_arg(t) := regex.find_n(_arg_re, trim_left(t, " \t"), 1)[0]

_refs(text, names) if {
	some n in names
	contains(text, n)
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `(?:\s*$|\s*[^\s:\w$])`]), text)
}

_binding(item) := v if {
	lhs := trim_space(split(item, "=")[0])
	parts := split(lhs, ":")
	v := trim_left(trim_space(parts[count(parts) - 1]), ".")
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

_destructured(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	contains(l, "{")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*(.*)$`, l, 1)
	count(m) > 0
	regex.match(_src, m[0][2])
	some item in split(m[0][1], ",")
	v := _binding(item)
}

# One further hop through an assignment that uses a tainted name, unless that
# assignment picks the value from a fixed list ([...].includes(x) ? x : y).
_tainted(lines, i) := t if {
	t1 := _direct(lines, i) | _destructured(lines, i)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		_refs(l, t1)
		v := helpers.assigned_first(l)
		not regex.match(`\]\s*\.includes\s*\(`, l)
	}
	t := t1 | t2
}

# Names assigned from a request value. A lookup keyed by one (a session
# fetched with req.cookies.token, a record found by req.params.id) returns
# server data, not the client's string.
_direct(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_src, l)
	not regex.match(_lookup_re, l)
	v := helpers.assigned_first(l)
}

_lookup_re := `=\s*(?:await\s+)?[\w.$?]+\.(?:get|findOne|findByPk|findById|findUnique|verify|decode|has)\(\s*(?:req|request|ctx)\b`

_reaches(a, _, _) if regex.match(_src, a)

_reaches(a, lines, i) if _refs(a, _tainted(lines, i))

_guard_re := `path\.basename\s*\(|\.startsWith\s*\(|\.(?:includes|indexOf)\s*\(\s*['"](?:\.\.|/|\\\\)|\bsanitize(?:[-_]?(?:filename|path))?\s*\(|\bsanitizeFilename\s*\(|\bisValid\w*\s*\(|/\^[^/\n]*\$/[gimsuy]*\.test\s*\(`

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 25, 0))

# send() (behind sendFile/download) refuses a path that leaves its root.
_rooted(sink, t) if {
	sink == _res_sink
	regex.match(`\broot\s*:`, t)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`\b(?:req|request|ctx)\.`, content)
	regex.match(`\bfs\b|fs/promises|fs-extra|sendFile|download`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _blank(line)
	some sink in _sinks_for(content)
	regex.match(sink, code)
	parts := regex.split(sink, line)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _call_text(lines, i, rest)
	not _rooted(sink, t)
	a := _first_arg(t)
	trim_space(a) != ""
	_reaches(a, lines, i)
	not _guarded(lines, i)
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
