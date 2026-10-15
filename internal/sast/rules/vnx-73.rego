# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_73

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-73",
	"name": "External Control of File Name or Path",
	"description": "The path argument of a file-system call is taken from the HTTP request, so the caller chooses which file is read, written, deleted or included. Sources: Flask/Django request.args/form/values/json/GET/POST/cookies/headers and Flask route <name> parameters; servlet getParameter/getHeader and Spring @RequestParam/@PathVariable/@RequestHeader parameters; Express req.query/body/params/headers/cookies, including destructured names; PHP $_GET/$_POST/$_REQUEST/$_COOKIE. Sinks (first argument only): Python open/io.open/send_file/FileResponse/os.remove/unlink/rename/listdir/makedirs/rmdir/shutil.*/Path(); Java new File/FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile, Paths.get, Path.of, Files.*, FileSystemResource; Node fs.readFile/createReadStream/writeFile/unlink/readdir/... and res.sendFile/res.download; PHP fopen/file_get_contents/file_put_contents/readfile/file/unlink/copy/rename/scandir/include/require(_once)/highlight_file/parse_ini_file. The request value is in that argument directly or through a variable assigned from the request (os.path.join, concatenation, a template) in the 20 lines above, or through one further variable built from such a name (name = request.POST[...]; target = os.path.join(base, name); open(target)). Not reported: send_from_directory and res.sendFile with a root option, a value passed through basename/secure_filename/FilenameUtils.getName/path.basename/an integer conversion, an allow-list, key-existence (array_key_exists, has, containsKey) or pattern check of the variable before the call, a canonical-path containment check right after building the File, request data written into a fixed file (a non-path argument), comments and strings. Go is covered by VNX-GO-007/VNX-GO-018.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-73/",
	"languages": ["java", "node", "php", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [73],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "file", "injection", "cwe-73"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_source_needles := {
	"py": {"request."},
	"java": {"getParameter", "getHeader", "@RequestParam", "@PathVariable", "@RequestHeader"},
	"js": {"req.", "request."},
	"php": {"$_"},
}

_source := {
	"py": `\b(?:\w+_)?request\.(args|form|values|json|get_json|GET|POST|cookies|headers|data|query_params)\b`,
	"java": `\.(getParameter|getParameterValues|getHeader)\s*\(`,
	"js": `\b(req|request)\.(query|body|params|headers|cookies)\b`,
	"php": `\$_(GET|POST|REQUEST|COOKIE)\b`,
}

# Sink call: the group-free prefix up to the opening parenthesis.
_sink := {
	"py": `(?:^|[^\w.])(?:open|io\.open|codecs\.open|send_file|FileResponse|os\.(?:remove|unlink|rename|listdir|scandir|makedirs|mkdir|rmdir|removedirs|stat|chmod)|shutil\.\w+|Path)\s*\(`,
	"java": `\bnew\s+(?:java\.io\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|FileSystemResource)\s*\(|\b(?:Paths\.get|Path\.of|Files\.\w+)\s*\(`,
	"js": `\b(?:fs|fsp|fsPromises|fs\.promises|fse)\.(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|readdir|readdirSync|open|openSync|rm|rmSync|copyFile|copyFileSync|rename|renameSync)\s*\(|\bres\.(?:sendFile|download)\s*\(`,
	"php": `(?:^|[^\w>:$])(?:fopen|file_get_contents|file_put_contents|readfile|file|unlink|copy|rename|scandir|opendir|highlight_file|show_source|parse_ini_file|include|include_once|require|require_once)\s*\(`,
}

_sink_needles := {
	"py": {"open(", "send_file(", "FileResponse(", "os.", "shutil.", "Path("},
	"java": {"new ", "Paths.get(", "Path.of(", "Files."},
	"js": {"fs", "res."},
	"php": {"(", "include", "require"},
}

# A balanced first argument, three parentheses deep.
_first_arg := `\s*((?:[^(),]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*)`

# include/require without parentheses
_php_bare := `(?:^|[^\w>:$])(?:include|include_once|require|require_once)\s+([^;(][^;]*)`

_sanitised := `(?i)\bbasename\s*\(|secure_filename|FilenameUtils\.getName|\bpath\.basename\s*\(|\bint\s*\(|\bintval\s*\(|Integer\.parseInt|parseInt\s*\(|Number\s*\(|saniti[sz]e`

_guard := `(?i)\bnot\s+in\b|array_key_exists|containsKey|hasOwnProperty|\.has\s*\(|\bin\s+[\w.]+\s*:|\.includes\s*\(|\bin_array\s*\(|\.contains\s*\(|\ballow|whitelist|preg_match\s*\(|\bre\.(full)?match\s*\(|\.matches\s*\(|\.test\s*\(|getCanonicalPath|toRealPath|realpath|\bswitch\b|\bcase\b`

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# The sink line, joined with the next two when the call is left open.
_call_text(lines, i, c) := c if count(regex.find_all_string_submatch_n(`\(`, c, -1)) <= count(regex.find_all_string_submatch_n(`\)`, c, -1))

_call_text(lines, i, c) := t if {
	count(regex.find_all_string_submatch_n(`\(`, c, -1)) > count(regex.find_all_string_submatch_n(`\)`, c, -1))
	e := min([count(lines) - 1, i + 2])
	t := concat(" ", array.concat([c], [_code(lines[k]) | some k in numbers.range(i + 1, e)]))
}

_is_sink(lang, c) if regex.match(_sink[lang], c)

_is_sink("php", c) if regex.match(_php_bare, c)

_args(lang, t) := (_call_args(lang, t) | _bare_args(lang, t)) | _all_args(lang, t)

# Constructors that join every argument into the path: new File(dir, name),
# Paths.get(base, a, b), Path.of(...).
_all_args(lang, t) := {a |
	lang == "java"
	some m in regex.find_all_string_submatch_n(`\b(?:new\s+(?:java\.io\.)?File|Paths\.get|Path\.of)\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, t, -1)
	a := m[1]
}

_call_args(lang, t) := {a |
	some m in regex.find_all_string_submatch_n(concat("", ["(?:", _sink[lang], ")", _first_arg]), t, -1)
	a := m[1]
}

_bare_args(lang, t) := {a |
	lang == "php"
	some m in regex.find_all_string_submatch_n(_php_bare, t, -1)
	a := m[1]
}

_name_re(lang, v) := concat("", [`\$`, v, `\b`]) if lang == "php"

_name_re(lang, v) := concat("", [`\b`, v, `\b`]) if lang != "php"

_assigned(lang, line) := m[0][1] if {
	lang == "php"
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, line, 1)
	count(m) > 0
}

_assigned(lang, line) := v if {
	lang != "php"
	v := helpers.assigned_first(line)
}

# Names that hold request data at line i, with the line they came from.
_tainted(lang, lines, i) := ((_t_assign(lang, lines, i) | _t_destructure(lang, lines, i)) | _t_spring(lang, lines, i)) | _t_route(lang, lines, i)

_t_assign(lang, lines, i) := {[v, j] |
	some j in numbers.range(max([0, i - 20]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_source[lang], _code(prev))
	not regex.match(_sanitised, prev)
	not _lookup_result(lang, prev)
	v := _assigned(lang, prev)
}

# Express: const { file, dir } = req.query;
_t_destructure(lang, lines, i) := {[v, j] |
	lang == "js"
	some j in numbers.range(max([0, i - 20]), i - 1)
	some m in regex.find_all_string_submatch_n(`\{([^}]*)\}\s*=\s*(req|request)\.(query|body|params)\b`, lines[j], 1)
	some part in split(m[1], ",")
	v := trim_space(split(part, ":")[count(split(part, ":")) - 1])
	regex.match(`^\w+$`, v)
}

# Spring handler parameters, and Flask route parameters.
_t_spring(lang, lines, i) := {[v, j] |
	lang == "java"
	some j in numbers.range(max([0, i - 30]), i)
	some m in regex.find_all_string_submatch_n(`@(RequestParam|PathVariable|RequestHeader)\b(\([^)]*\))?\s+(final\s+)?([\w<>\[\].]+)\s+(\w+)`, lines[j], -1)
	# an uploaded part is not a path; its client file name is VNX-66's
	not regex.match(`MultipartFile|\bPart\b`, m[4])
	v := m[5]
}

_t_route(lang, lines, i) := {[v, j] |
	lang == "py"
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], "<")
	some m in regex.find_all_string_submatch_n(`@\w+\.(route|get|post|put|delete)\s*\(\s*["'][^"']*<(\w+:)?(\w+)>`, lines[j], -1)
	v := m[3]
}

_reaches(lang, _, _, arg) if regex.match(_source[lang], arg)

_reaches(lang, lines, i, arg) if {
	some pair in _tainted(lang, lines, i)
	re := _name_re(lang, pair[0])
	regex.match(re, arg)
	not _guarded(lines, pair[1], i, re)
}

# One more hop: a path variable built from a request-derived name
# (file = request.POST["f"]; filename = os.path.join(base, file); open(filename)).
_reaches(lang, lines, i, arg) if {
	some pair in _tainted(lang, lines, i)
	re := _name_re(lang, pair[0])
	not regex.match(re, arg)
	some k in numbers.range(pair[1] + 1, i - 1)
	prev := lines[k]
	regex.match(re, _code(prev))
	not helpers.is_comment_line(prev)
	not regex.match(_sanitised, prev)
	not regex.match(_guard, prev)
	not _lookup_result(lang, prev)
	# a hop that is itself a file call (new File(base, name)) is reported there
	not _is_sink(lang, _code(prev))
	w := _assigned(lang, prev)
	w != pair[0]
	re2 := _name_re(lang, w)
	regex.match(re2, arg)
	not _guarded(lines, pair[1], i, re)
	not _guarded(lines, k, i, re2)
}

_guarded(lines, j, i, re) if {
	some k in numbers.range(j + 1, i - 1)
	l := lines[k]
	regex.match(re, l)
	regex.match(_guard, l)
	not helpers.is_comment_line(l)
}

# new File(...) assigned to a name that a canonical containment check reads
# within the next six lines.
_checked_after(lines, i, line) if {
	v := helpers.assigned_first(line)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
	regex.match(concat("", [`\b`, v, `\.(getCanonicalPath|getCanonicalFile|toRealPath|normalize)\s*\(`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _source_needles[lang])
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _sink_needles[lang])
	not helpers.is_comment_line(line)
	c := _code(line)
	_is_sink(lang, c)
	not regex.match(`\bres\.(sendFile|download)\s*\([^;]*\broot\s*:`, c)
	not regex.match(_logging, c)
	t := _call_text(lines, i, c)
	some arg in _args(lang, t)
	not regex.match(_sanitised, arg)
	_reaches(lang, lines, i, arg)
	not _checked_after(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "The path given to this file operation comes from the HTTP request, so the caller decides which file is read, written, deleted or included (../../etc/passwd, an absolute path, another user's file). Map the request to a known file (an id or an allow-list), or reduce it to a bare name with basename/secure_filename and confirm the canonical result stays inside the intended directory",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A record looked up by a request value (users.get(req.cookies.token),
# User.query.get(request.args["id"])) is the server's data, not the request.
_lookup_result(lang, prev) if {
	lang != "php"
	regex.match(concat("", [`\.(get|find\w*|lookup|load\w*|fetch\w*|query|filter\w*)\s*\([^)]*(`, _source[lang], `)`]), prev)
}

# A path printed in a log line is not opened.
_logging := `(?i)\b(log|logger|logging|console|slf4j)\s*\.\s*(debug|info|warn\w*|error|trace|log)\s*\(`
