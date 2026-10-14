package vulnetix.rules.vnx_go_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-009",
	"name": "Go text/template used for HTML",
	"description": "A template from text/template (which never HTML-escapes) is rendered into a web response or loaded from HTML files. Reported: Execute/ExecuteTemplate on a template built with text/template in the same file (text/template's local name, an alias included, is resolved from the import; a Lookup/Funcs chain such as t.Lookup(\"row\").Execute counts) whose writer is the handler's response: a parameter declared http.ResponseWriter, *fasthttp.RequestCtx or fiber.Ctx, gin's c.Writer, echo's c.Response(), the io.Writer of an echo Renderer, or a bufio/gzip writer wrapped around one of these in the same function; and ParseFiles/ParseGlob/ParseFS of .html, .htm, .gohtml or .xhtml files with text/template, including ParseFiles(files...) over a slice literal of such names. Not reported: html/template (including a file that imports both and renders the page with html/template), text/template rendering code, YAML, shell, config or JSON into files, buffers, stdout or HTTP request bodies, a response whose handler first sets a Content-Type that is not HTML or SVG (text/plain, a shell script, YAML, JSON), comments and strings that merely name the package. Templates defined in one file and executed in another are matched only through the ParseFiles/ParseGlob signal.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-009/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "template", "html"],
}

# An import of text/template, bare or aliased, in an import block or a single
# import. A trailing comma (a string in a slice) is not an import.
_txt_import_re := `(?m)^\s*(?:import\s+)?(?:([A-Za-z_]\w*)\s+)?"text/template"\s*(?://.*)?$`

# text/template's local name in this file. A blank or dot import gives none.
_txt_pkg(content) := name if {
	m := regex.find_all_string_submatch_n(_txt_import_re, content, 1)
	count(m) > 0
	m[0][1] == ""
	name := "template"
}

_txt_pkg(content) := name if {
	m := regex.find_all_string_submatch_n(_txt_import_re, content, 1)
	count(m) > 0
	m[0][1] != ""
	name := m[0][1]
}

# Names that hold a text/template template in this file: assigned from the
# package's constructors, a struct-literal field set from one, or declared
# *<pkg>.Template.
_tmpl_names(lines, pkg) := {n |
	some line in lines
	not helpers.is_comment_line(line)
	some re in [
		concat("", [`\b(\w+)\s*(?:,\s*\w+\s*)?:?=\s*`, pkg, `\.(?:Must|New|ParseFiles|ParseGlob|ParseFS)\(`]),
		concat("", [`\b(\w+)\s*:\s*`, pkg, `\.(?:Must|New|ParseFiles|ParseGlob|ParseFS)\(`]),
		concat("", [`\b(\w+)\s+\*`, pkg, `\.Template\b`]),
	]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	n := m[1]
	n != "_"
}

# Start of the enclosing top-level function.
_fn_start(lines, i) := max(starts) if {
	starts := {j | some j in numbers.range(0, i); startswith(lines[j], "func ")}
	count(starts) > 0
}

_fn_start(lines, i) := 0 if {
	not _any_func_above(lines, i)
}

_any_func_above(lines, i) if {
	some j in numbers.range(0, i)
	startswith(lines[j], "func ")
}

_fn_text(lines, i) := helpers.code_window(lines, i, i - _fn_start(lines, i), 0)

# The template's first argument: on the call line, or on the next code line
# when the call is broken after its parenthesis.
_first_arg(line, _, _) := a if {
	m := regex.find_all_string_submatch_n(`\.(?:Execute|ExecuteTemplate)\(\s*([^,]+?)\s*(?:,|$)`, line, 1)
	count(m) > 0
	a := m[0][1]
}

_first_arg(line, lines, i) := a if {
	regex.match(`\.(?:Execute|ExecuteTemplate)\(\s*$`, line)
	j := helpers.next_code_index(lines, i, 3)
	m := regex.find_all_string_submatch_n(`^\s*([^,]+?)\s*,`, lines[j], 1)
	count(m) > 0
	a := m[0][1]
}

# The writer is the HTTP response...
_resp_writer(arg, fn) if _resp_writer_base(arg, fn)

# ...or a buffering/compressing writer wrapped around it in the same function
# (bw := bufio.NewWriter(w); gz := gzip.NewWriter(w)).
_resp_writer(arg, fn) if {
	regex.match(`^\w+$`, arg)
	some m in regex.find_all_string_submatch_n(concat("", [`\b`, arg, `\s*(?:,\s*\w+\s*)?:?=\s*\w+\.NewWriter\w*\(\s*([^,)]+?)\s*[,)]`]), fn, -1)
	_resp_writer_base(m[1], fn)
}

_resp_writer_base(arg, _) if regex.match(`^\w+\.Response\(\)(?:\.Writer)?$`, arg)

_resp_writer_base(arg, fn) if {
	regex.match(`^\w+\.Writer$`, arg)
	contains(fn, "gin.Context")
}

_resp_writer_base(arg, fn) if {
	regex.match(`^\w+$`, arg)
	regex.match(concat("", [`\b`, arg, `\s+(?:http\.ResponseWriter|\*fasthttp\.RequestCtx|\*?fiber\.Ctx)\b`]), fn)
}

# echo.Renderer: Render(w io.Writer, name string, data interface{}, c echo.Context)
_resp_writer_base(arg, fn) if {
	regex.match(`^\w+$`, arg)
	regex.match(concat("", [`(?m)^.*\b`, arg, `\s+io\.Writer\b.*echo\.Context.*$`]), fn)
}

# The handler declares a response type that a browser does not render as
# HTML (text/plain, a shell script, YAML, JSON...) before rendering.
_non_html_type(fn) if {
	some m in regex.find_all_string_submatch_n(`(?i)content-type"\s*,\s*"([^"]+)"`, fn, -1)
	not regex.match(`(?i)html|svg`, m[1])
}

_non_html_type(fn) if regex.match(`HeaderContentType\s*,\s*echo\.MIME(?:TextPlain|ApplicationJSON|ApplicationXML|OctetStream)`, fn)

# The receiver of Execute is a text/template template, directly or through
# a lookup chain (t.Lookup("row").Execute, t.Funcs(fm).Execute).
_text_receiver(line, names, _) if {
	some m in regex.find_all_string_submatch_n(`\b(\w+)(?:\.(?:Lookup|Funcs|Option|Delims)\([^)]*\))*\.(?:Execute|ExecuteTemplate)\(`, line, -1)
	m[1] in names
}

_text_receiver(line, _, pkg) if {
	regex.match(concat("", [`\b`, pkg, `\.(?:Must|New)\(.*\)\.(?:Execute|ExecuteTemplate)\(`]), line)
}

_execute_sink(lines, i, line, names, pkg) if {
	regex.match(`\.(?:Execute|ExecuteTemplate)\(`, line)
	_text_receiver(line, names, pkg)
	arg := _first_arg(line, lines, i)
	fn := _fn_text(lines, i)
	_resp_writer(arg, fn)
	not _non_html_type(fn)
}

_html_file_re := `"[^"\n]*\.(?:html?|gohtml|xhtml)(?:\.tmpl)?"`

# text/template loads HTML files.
_parse_html_sink(lines, i, line, names, pkg) if {
	_parses_with_text(line, names, pkg)
	_names_html_file(lines, i, line)
}

_parses_with_text(line, _, pkg) if {
	regex.match(concat("", [`\b`, pkg, `\.(?:ParseFiles|ParseGlob)\(`]), line)
}

_parses_with_text(line, _, pkg) if {
	regex.match(concat("", [`\b`, pkg, `\.(?:New|Must)\(.*\.(?:ParseFiles|ParseGlob|ParseFS)\(`]), line)
}

_parses_with_text(line, names, _) if {
	some m in regex.find_all_string_submatch_n(`\b(\w+)\.(?:ParseFiles|ParseGlob|ParseFS)\(`, line, -1)
	m[1] in names
}

_names_html_file(_, _, line) if regex.match(_html_file_re, line)

# ParseFiles(files...) over a slice literal of .html names in this file.
_names_html_file(lines, _, line) if {
	some m in regex.find_all_string_submatch_n(`\.ParseFiles\(\s*(\w+)\.\.\.`, line, -1)
	decl := concat("", [`\b`, m[1], `\s*:?=\s*\[\]string\{.*`, _html_file_re])
	some l in lines
	regex.match(decl, l)
	not helpers.is_comment_line(l)
}

_names_html_file(lines, i, line) if {
	regex.match(`\.(?:ParseFiles|ParseGlob|ParseFS)\(\s*$`, line)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(_html_file_re, lines[j])
}

_sink(lines, i, line, names, pkg) if _execute_sink(lines, i, line, names, pkg)

_sink(lines, i, line, names, pkg) if _parse_html_sink(lines, i, line, names, pkg)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "\"text/template\"")
	pkg := _txt_pkg(content)
	lines := split(content, "\n")
	names := _tmpl_names(lines, pkg)
	some i, line in lines
	regex.match(`\.(?:Execute|ExecuteTemplate|ParseFiles|ParseGlob|ParseFS)\(`, line)
	not helpers.is_comment_line(line)
	_sink(lines, i, line, names, pkg)
	finding := {
		"rule_id": metadata.id,
		"message": "A text/template template renders HTML (it is written to the HTTP response, or loaded from .html files); text/template does not escape {{.}} values, so request data becomes markup. Use html/template",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
