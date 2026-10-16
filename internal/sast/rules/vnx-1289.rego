# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1289

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1289",
	"name": "Improper Validation of Unsafe Equivalence in Input",
	"description": "An uploaded file name is checked against a denylist of dangerous extensions with a case-sensitive comparison, so an equivalent name the server still treats as dangerous (shell.PHP, page.Html, run.EXE) passes the check. Reported in Python (Flask/Werkzeug FileStorage .filename, Django request.FILES[...].name, also through a file object assigned from request.FILES) and JavaScript/TypeScript (multer/formidable originalname/originalFilename, req.file(s) .name): .endswith()/.endsWith() with a dangerous extension literal (php, phtml, phar, exe, bat, cmd, sh, jsp, asp/aspx, py, pl, cgi, js, html/htm/shtml/svg, dll, jar/war, ps1, vbs, hta, htaccess and similar), membership of the name or its extension (os.path.splitext, path.extname) in an inline or module-level list/tuple/set of such extensions (in, .includes(), .has()), or == / === against one, applied to the upload name directly or through a variable assigned from it in the 15 lines above. Not reported: a name or extension lowered first (.lower(), .casefold(), .toLowerCase()), allowlist checks whose extensions are harmless (png, jpg, zip), extension tests on names that are not uploads (os.walk results, module paths), comments and string literals. Other unsafe equivalences (Unicode normalisation, trailing dots, alternate path separators) are not detected.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1289/",
	"languages": ["python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1289],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["input-validation-inconsistent", "cwe-1289"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_lang(path) := "js" if {
	some e in _js_exts
	endswith(path, e)
	not endswith(path, ".min.js")
	not contains(path, "node_modules/")
}

_lang(path) := "py" if endswith(path, ".py")

_bad_ext := `['"]\.?(?:php\d?|phtml|phar|pht|exe|bat|cmd|com|sh|bash|jsp|jspx|asp|aspx|ashx|asmx|cer|py|pyc|pl|cgi|rb|js|mjs|html?|xhtml|shtml|svg|swf|dll|so|war|jar|ps1|vbs|hta|htaccess|scr|msi)['"]`

_upload := {
	"py": `\.filename\b|\brequest\.FILES\b[^\n]*\.name\b`,
	"js": `\.(?:originalname|originalFilename)\b|\breq\.files?\b[\w.\[\]'"]*\.name\b`,
}

_lowered := `\.(?:lower|casefold|toLowerCase|toLocaleLowerCase)\(`

# Expressions that are the raw upload name.
_direct := {
	"py": `(?:\w+(?:\[[^\]]*\])?\.filename|request\.FILES\[[^\]]+\]\.name)`,
	"js": `(?:[\w$]+(?:\?\.|\.)(?:file|files\??\.\w+)?(?:\?\.|\.)?(?:originalname|originalFilename)|req\.files?(?:\.\w+)?\.name)`,
}

_names(lines, i, lang) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	regex.match(_upload[lang], prev)
	not regex.match(_lowered, prev)
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*[^=]`, prev, 1)
	count(m) > 0
	v := m[0][1]
	not _relowered(lines, j, i, v)
}

# One more hop: a name or extension derived from a name already known to be
# the upload name (name = up.name, ext = path.extname(original)).
_names_all(lines, i, lang) := _names(lines, i, lang) | {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not regex.match(_lowered, prev)
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*([^=].*)$`, prev, 1)
	count(m) > 0
	v := m[0][1]
	rhs := m[0][2]
	some src in (_names(lines, j, lang) | {x | some f in _django_files(lines, j, lang); x := concat("", [f, ".name"])})
	regex.match(concat("", [`\b`, src, `\b`]), rhs)
	not _relowered(lines, j, i, v)
}

_relowered(lines, j, i, v) if {
	some k in numbers.range(j + 1, i)
	regex.match(concat("", [`\b`, v, `\s*=\s*[^=][^\n]*`, _lowered]), lines[k])
}

_exprs(lines, i, lang) := ({_direct[lang]} | {concat("", [`\b`, v, `\b`]) | some v in _names_all(lines, i, lang)}) | {concat("", [`\b`, v, `\.name`]) | some v in _django_files(lines, i, lang)}

# Django: f = request.FILES["doc"] (or .get(...)), or for f in
# request.FILES.getlist(...); f.name is then the upload name.
_django_files(lines, i, "py") := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	contains(prev, "request.FILES")
	not helpers.is_comment_line(prev)
	m := regex.find_all_string_submatch_n(`^\s*(?:(\w+)\s*=\s*request\.FILES\s*(?:\[|\.get\()|for\s+(\w+)\s+in\s+request\.FILES\.getlist\()`, prev, 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2]])
}

_django_files(_, _, "js") := set()

# Module-level names bound to a collection holding a dangerous extension.
_bad_lists(lines) := {n |
	some j, l in lines
	contains(l, "=")
	regex.match(`[\[\(\{]`, l)
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=\s*(?:new Set\(\s*|frozenset\(\s*|set\(\s*)?[\[\(\{]`, l, 1)
	count(m) > 0
	_holds_bad_ext(lines, j, l)
	n := m[0][1]
}

_holds_bad_ext(_, _, l) if regex.match(_bad_ext, l)

# A collection spread over the following lines, before it closes.
_holds_bad_ext(lines, j, l) if {
	not regex.match(_bad_ext, l)
	not regex.match(`[\]\)\}]`, l)
	w := concat("\n", array.slice(lines, j + 1, min([j + 16, count(lines)])))
	regex.match(concat("", [`^[^\]\)\}]*`, _bad_ext]), w)
}

# endswith with a dangerous literal on the line or the 3 lines after.
_sink(lines, i, c, e, _) if {
	regex.match(concat("", [`(?:^|[^\w.$])`, e, `\.(?:endswith|endsWith)\(`]), c)
	w := concat("\n", array.slice(lines, i, min([i + 4, count(lines)])))
	regex.match(concat("", [`(?:endswith|endsWith)\(\s*\(?[^)]*`, _bad_ext]), regex.replace(w, `\n`, " "))
}

# The name itself, or its extension taken with rsplit/rpartition/splitext/extname.
_ext_of(e) := concat("", [`(?:`, e, `(?:\.r?(?:split|partition)\([^)]*\)\[-?\d+\])?|(?:os\.)?(?:path\.)?(?:splitext|extname)\(\s*`, e, `\s*\)(?:\[-?\d+\])?)`])

# membership in an inline collection
_sink(_, _, c, e, _) if {
	regex.match(concat("", [`(?:^|[^\w.$])`, _ext_of(e), `\s+(?:not\s+)?in\s+[\[\(\{][^\]\)\}]*`, _bad_ext]), c)
}

_sink(_, _, c, e, _) if {
	regex.match(concat("", [`\[[^\]]*`, _bad_ext, `[^\]]*\]\s*\.(?:includes|indexOf)\(\s*`, _ext_of(e), `\s*\)`]), c)
}

# membership in a named collection
_sink(lines, _, c, e, lists) if {
	some n in lists
	x := _ext_of(e)
	regex.match(concat("", [`(?:^|[^\w.$])`, x, `\s+(?:not\s+)?in\s+`, n, `\b|\b`, n, `\s*\.(?:includes|has|indexOf)\(\s*`, x, `\s*\)`]), c)
}

# equality against one dangerous extension
_sink(_, _, c, e, _) if {
	x := _ext_of(e)
	regex.match(concat("", [`(?:^|[^\w.$])`, x, `\s*[!=]==?\s*`, _bad_ext, `|`, _bad_ext, `\s*[!=]==?\s*`, x, `(?:$|[^\w.(\[])`]), c)
}

# A case-sensitive regular expression naming a dangerous extension:
# /\.(php|exe)$/.test(name) without the i flag, re.search(r"\.(sh|cgi)$", name)
# without re.I/re.IGNORECASE or (?i).
_sink(_, _, c, e, _) if {
	regex.match(concat("", [`/[^/\n]*\b`, _bad_word, `\b[^/\n]*/[gmsuy]*\.test\(\s*`, _ext_of(e), `\s*\)`]), c)
}

_sink(_, _, c, e, _) if {
	m := regex.find_all_string_submatch_n(concat("", [`\bre\.(?:search|match|fullmatch)\(\s*[rR]?(?:"([^"]*)"|'([^']*)')\s*,\s*`, _ext_of(e), `\s*\)`]), c, -1)
	some x in m
	pat := concat("", [x[1], x[2]])
	regex.match(concat("", [`\b`, _bad_word, `\b`]), pat)
	not contains(pat, "(?i")
}

_bad_word := `(?:php\d?|phtml|phar|pht|exe|bat|cmd|sh|bash|jsp|jspx|asp|aspx|ashx|asmx|py|pyc|pl|cgi|rb|html?|xhtml|shtml|svg|swf|dll|war|jar|ps1|vbs|hta|htaccess|scr|msi)`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_upload(content, lang)
	_has_bad_ext(content)
	lines := split(content, "\n")
	lists := _bad_lists(lines)
	some i, line in lines
	regex.match(`endswith|endsWith|\bin\b|includes|indexOf|\.has\(|==|\.test\(|\bre\.(?:search|match|fullmatch)\(`, line)
	not helpers.is_comment_line(line)
	not _in_string(line)
	some e in _exprs(lines, i, lang)
	_sink(lines, i, line, e, lists)
	finding := {
		"rule_id": metadata.id,
		"message": "Upload name is compared with a dangerous-extension denylist case-sensitively; 'shell.PHP' passes. Lower-case the name first (or use an allowlist)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The whole statement is a string literal assignment (help text, docs).
_in_string(line) if regex.match(`^\s*[A-Za-z_]\w*\s*=\s*['"][^'"]*(?:endswith|endsWith)`, line)

_has_upload(content, lang) if regex.match(_upload[lang], content)

_has_upload(content, "py") if contains(content, "request.FILES")

_has_bad_ext(content) if regex.match(_bad_ext, content)

_has_bad_ext(content) if regex.match(concat("", [`\\\.\(?[\w|]*\b`, _bad_word, `\b`]), content)
