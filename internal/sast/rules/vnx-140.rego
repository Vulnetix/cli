# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_140

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-140",
	"name": "Improper Neutralization of Delimiters",
	"description": "Reports Python and JavaScript/TypeScript code that writes a delimited record (CSV, TSV, pipe- or colon-separated line) to a file or stream by gluing request data together with the delimiter, without quoting or escaping it: f.write(f\"{name},{email}\\n\"), out.write(user + \":\" + role), \"|\".join([...]), \"%s,%s\" % (...), \"{},{}\".format(...), fs.appendFileSync('a.csv', `${req.body.a},${req.body.b}`), [..].join(','), either on the write itself or in a record variable built in the 6 lines above it. A value containing the delimiter (or a newline) then adds fields or records. The data must come from the request on that line (Flask/Django request.form/args/values/json/data/cookies/headers/GET/POST, Express/Koa req/ctx body/query/params/cookies/headers) or from a variable assigned from it in the 10 lines above. Sinks are .write(), .writelines(), print(..., file=...) and fs.appendFile/writeFile (and their Sync forms); HTTP response writes (res.write, response.write, self.wfile) are not this weakness and are not reported. Not reported: csv.writer/DictWriter, csv-stringify, json.dumps/JSON.stringify, values passed through .replace()/re.sub()/quote()/escape() first, constant header rows, data that does not come from the request, comments and string literals. Parsing the other way (splitting input on a delimiter) is VNX-166.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-140/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [140],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["delimiter", "injection", "csv", "cwe-140"],
}

_py_src := `\b(?:self\.)?request\.(?:form|args|values|json|get_json|data|cookies|COOKIES|headers|GET|POST|META|query_params)\b`

_js_src := `\b(?:req|request)\.(?:body|query|params|cookies|signedCookies|headers|get\s*\(|header\s*\()|\bctx\.(?:request|query|params|cookies|headers)\b`

_lang_of(path) := "py" if endswith(path, ".py")

_lang_of(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
}

_src("py") := _py_src

_src("js") := _js_src

_sink_lit(s) if contains(s, ".write")

_sink_lit(s) if contains(s, "appendFile")

_sink_lit(s) if contains(s, "writeFile")

_sink_lit(s) if contains(s, "print(")

_files := {path: [lang, split(content, "\n")] |
	some path, content in input.file_contents
	_sink_lit(content)
	lang := _lang_of(path)
	not endswith(path, ".min.js")
	regex.match(_src(lang), content)
}

_d := `(?:,|\||;|\\t|:)`

# A string built by joining values with a delimiter.
_delimited(line) if regex.match(concat("", [`\b[rR]?[fF][rR]?["'][^"'\n]*\{[^{}]+\}\s*`, _d, `\s*\{`]), line)

_delimited(line) if regex.match(concat("", ["`[^`\\n]*\\$\\{[^{}]+\\}\\s*", _d, "\\s*\\$\\{"]), line)

_delimited(line) if regex.match(concat("", [`\+\s*["']`, _d, `["']\s*\+`]), line)

_delimited(line) if regex.match(concat("", [`["']`, _d, `["']\.join\(`]), line)

_delimited(line) if regex.match(concat("", [`\.join\(\s*["']`, _d, `["']\s*\)`]), line)

_delimited(line) if regex.match(concat("", [`["'][^"'\n]*%[sdr]\s*`, _d, `\s*%[sdr][^"'\n]*["']\s*%`]), line)

_delimited(line) if regex.match(concat("", [`["'][^"'\n]*\{\w*\}\s*`, _d, `\s*\{\w*\}[^"'\n]*["']\.format\(`]), line)

_sanitised(line) if regex.match(`\bjson\.dumps\s*\(|\bJSON\.stringify\s*\(|\bstringify\s*\(|\bquote\s*\(|\bescape\w*\s*\(|\.replace\s*\(|\bre\.sub\s*\(|encodeURIComponent\s*\(`, line)

_sink(line) if {
	regex.match(`\.(?:write|writelines)\s*\(|\b(?:appendFile|appendFileSync|writeFile|writeFileSync)\s*\(|\bprint\s*\(.*\bfile\s*=`, line)
	not regex.match(`\b(?:res|response|resp|reply|document|wfile|ctx\.res|ctx\.body)\.write`, line)
}

# Names assigned from the request (not through a sanitiser) in the 10 lines above.
_tainted(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(src, l)
	not _sanitised(l)
	v := _assigned(l)
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_]\w*)\s*:\s*[^=]+=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
} else := helpers.assigned_first(line)

_carries(lines, i, lang) if {
	regex.match(_src(lang), lines[i])
	_src_outside_string(lines[i], lang)
}

_carries(lines, i, lang) if {
	some v in _tainted(lines, i, _src(lang))
	regex.match(concat("", [`\b`, v, `\b`]), lines[i])
}

# The request expression sits in code, not inside a quoted string.
_src_outside_string(line, lang) if {
	m := regex.find_all_string_submatch_n(_src(lang), line, 1)[0]
	off := indexof(line, m[0])
	pre := substring(line, 0, off)
	count(indexof_n(pre, `"`)) % 2 == 0
	count(indexof_n(pre, "'")) % 2 == 0
}

_src_outside_string(line, lang) if {
	# inside a template literal's ${...}
	m := regex.find_all_string_submatch_n(_src(lang), line, 1)[0]
	pre := substring(line, 0, indexof(line, m[0]))
	count(indexof_n(pre, "${")) > 0
}

_src_outside_string(line, "py") if {
	# inside an f-string's {...}
	m := regex.find_all_string_submatch_n(_src("py"), line, 1)[0]
	pre := substring(line, 0, indexof(line, m[0]))
	regex.match(`\b[fF]["'][^"']*\{[^}]*$`, pre)
}

_msg := "A delimited record is built from request data and written without quoting the values: a value containing the delimiter or a newline adds fields or whole records; use the csv module / a CSV library, or reject or escape the delimiter first"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# Write calls, located once per file; both checks start from them.
_sinks contains [path, i] if {
	some path, entry in _files
	some i, line in entry[1]
	_sink_lit(line)
	_sink(line)
	not helpers.is_comment_line(line)
}

# (A) the record is built on the write itself
findings contains f if {
	some s in _sinks
	[path, i] := s
	[lang, lines] := _files[path]
	line := lines[i]
	_delimited(line)
	not _sanitised(line)
	_carries(lines, i, lang)
	f := _finding(path, i, line)
}

# (B) record = <delimited build>; <sink>(record)
findings contains f if {
	some s in _sinks
	[path, i] := s
	[lang, lines] := _files[path]
	sink := lines[i]
	not _delimited(sink)
	some k in numbers.range(max([0, i - 6]), i - 1)
	def := lines[k]
	not helpers.is_comment_line(def)
	_delimited(def)
	not _sanitised(def)
	r := _assigned(def)
	regex.match(concat("", [`\(.*\b`, r, `\b`]), sink)
	_carries(lines, k, lang)
	f := _finding(path, i, sink)
}
