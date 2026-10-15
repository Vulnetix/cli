# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_776

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-776",
	"name": "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
	"description": "Untrusted XML is parsed by a parser that expands nested internal entities without a limit, so a few kilobytes of nested entity definitions (billion laughs, quadratic blowup) exhaust memory and CPU. Reported: in Python, the standard library parsers (xml.etree.ElementTree/cElementTree fromstring/XML/parse/iterparse/fromstringlist, xml.dom.minidom and pulldom parse/parseString, xml.sax parse/parseString, under any import alias or imported by name) and xmltodict.parse given request data, an upload stream, stdin, urlopen() or a requests response, directly or through a variable assigned from one up to 25 lines above (one intermediate assignment such as .decode() is followed); lxml XMLParser(huge_tree=True), which switches libxml2's expansion limits off; in PHP, LIBXML_PARSEHUGE passed to a libxml loader; in JavaScript/TypeScript, libxmljs parseXml/parseXmlString with huge: true and libxml2-wasm XML_PARSE_HUGE. Not reported: defusedxml (or a file calling defusedxml.defuse_stdlib()), the standard parsers given a constant, a local path or a function parameter of unknown origin, lxml with its default limits, Java factories (VNX-JAVA-024 covers those), external entity resolution (XXE, VNX-PY-014), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-776/",
	"languages": ["python", "php", "node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [776],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["xml-bomb", "billion-laughs", "cwe-776"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# String literals blanked, so a call quoted in a message or docstring is not code.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# ── Python standard library parsers on untrusted data ────────────────────

# Module aliases that name a standard-library (or xmltodict) parser module.
_py_module_aliases(content) := {a |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+(xml\.etree\.c?ElementTree|xml\.dom\.minidom|xml\.dom\.pulldom|xml\.sax|xmltodict)(?:\s+as\s+(\w+))?`, content, -1)
	a := _alias_or(m[2], m[1])
} | {a |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+(xml\.etree|xml\.dom|xml)\s+import\s+([^\n#]+)`, content, -1)
	some part in split(trim(m[2], "()"), ",")
	pm := regex.find_all_string_submatch_n(`^\s*(c?ElementTree|minidom|pulldom|sax)(?:\s+as\s+(\w+))?\s*$`, part, 1)
	count(pm) > 0
	a := _alias_or(pm[0][2], pm[0][1])
}

_alias_or(alias, name) := alias if alias != ""

_alias_or(alias, name) := name if alias == ""

# Parser functions imported by name: `from xml.etree.ElementTree import fromstring`.
_py_bare_funcs(content) := {a |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+(?:xml\.etree\.c?ElementTree|xml\.dom\.minidom|xml\.dom\.pulldom|xml\.sax|xmltodict)\s+import\s+([^\n#]+)`, content, -1)
	some part in split(trim(m[1], "()"), ",")
	pm := regex.find_all_string_submatch_n(`^\s*(fromstring|fromstringlist|XML|parse|iterparse|parseString)(?:\s+as\s+(\w+))?\s*$`, part, 1)
	count(pm) > 0
	a := _alias_or(pm[0][2], pm[0][1])
}

_py_parse_funcs := `(?:fromstring|fromstringlist|XML|parse|iterparse|parseString)`

_esc(s) := replace(s, ".", `\.`)

# The argument text of a parser call on line i (the rest of the line, plus the
# next lines when the call is split).
_py_call_args(lines, i, prefix_re) := args if {
	c := _code(lines[i])
	m := regex.find_all_string_submatch_n(concat("", [prefix_re, `\s*\((.*)$`]), c, 1)
	count(m) > 0
	end := min([count(lines) - 1, i + 3])
	rest := [_code(lines[k]) | some k in numbers.range(i + 1, end)]
	args := concat(" ", array.concat([m[0][1]], rest))
}

_py_sink_args(lines, i, aliases, funcs) := {args |
	some a in aliases
	contains(lines[i], a)
	args := _py_call_args(lines, i, concat("", [`(?:^|[^\w.])`, _esc(a), `\.`, _py_parse_funcs]))
} | {args |
	some f in funcs
	contains(lines[i], f)
	args := _py_call_args(lines, i, concat("", [`(?:^|[^\w.])`, f]))
}

_py_source := `\brequest\.(?:data|body|get_data|files|FILES|stream|form|POST|values|json|get_json)\b|\brequest\.read\(|\burlopen\s*\(|\brequests\.(?:get|post|put|request)\s*\(|\bsys\.stdin\b|\bself\.rfile\b|wsgi\.input|\bhttpx\.(?:get|post)\s*\(`

# A name the argument uses that was assigned from a source above (or from
# a line that used such a name: `text = payload.decode()`).
_py_tainted(lines, i) := names if {
	direct := helpers.tainted_names(lines, i, 25, _py_source)
	hop := {v |
		some d in direct
		some j in numbers.range(max([0, i - 25]), i - 1)
		not helpers.is_comment_line(lines[j])
		regex.match(concat("", [`=.*\b`, d, `\b`]), lines[j])
		v := helpers.assigned_first(lines[j])
	}
	names := direct | hop
}

_py_untrusted(lines, i, args) if regex.match(_py_source, args)

_py_untrusted(lines, i, args) if {
	some v in _py_tainted(lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), args)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*(?:import|from)\s+(?:xml(?:\.|\s)|xmltodict)`, content)
	not contains(content, "defuse_stdlib()")
	aliases := _py_module_aliases(content)
	funcs := _py_bare_funcs(content)
	count(aliases) + count(funcs) > 0
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	some args in _py_sink_args(lines, i, aliases, funcs)
	_py_untrusted(lines, i, args)
	f := _finding(path, i, line, "Untrusted XML parsed with a standard-library parser that expands nested entities; use defusedxml (or lxml with its default limits)")
}

# lxml with the expansion limits removed.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "huge_tree")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "huge_tree")
	not helpers.is_comment_line(line)
	regex.match(`\bhuge_tree\s*=\s*True\b`, _code(line))
	window := helpers.code_window(lines, i, 4, 0)
	regex.match(`XMLParser\s*\(|XMLPullParser\s*\(|iterparse\s*\(|XMLSchema\s*\(`, window)
	f := _finding(path, i, line, "lxml huge_tree=True disables libxml2's entity-expansion and depth limits; remove it for untrusted input")
}

# ── PHP: LIBXML_PARSEHUGE ────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "LIBXML_PARSEHUGE")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "LIBXML_PARSEHUGE")
	not helpers.is_comment_line(line)
	regex.match(`\bLIBXML_PARSEHUGE\b`, _code(line))
	f := _finding(path, i, line, "LIBXML_PARSEHUGE removes libxml2's entity-expansion and size limits; do not pass it when parsing untrusted XML")
}

# ── JavaScript / TypeScript: libxmljs huge, libxml2-wasm XML_PARSE_HUGE ──

_js_ext := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}

findings contains f if {
	some path, content in input.file_contents
	some ext in _js_ext
	endswith(path, ext)
	contains(content, "XML_PARSE_HUGE")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "XML_PARSE_HUGE")
	not helpers.is_comment_line(line)
	regex.match(`\bXML_PARSE_HUGE\b`, _code(line))
	f := _finding(path, i, line, "XML_PARSE_HUGE removes libxml2's entity-expansion and size limits; do not pass it when parsing untrusted XML")
}

findings contains f if {
	some path, content in input.file_contents
	some ext in _js_ext
	endswith(path, ext)
	contains(content, "huge")
	regex.match(`parseXml(?:String)?\s*\(|parseHtml(?:String)?\s*\(|SaxParser|SaxPushParser`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "huge")
	not helpers.is_comment_line(line)
	regex.match(`\bhuge\s*:\s*true\b`, _code(line))
	window := helpers.code_window(lines, i, 4, 0)
	regex.match(`parseXml(?:String)?\s*\(|parseHtml(?:String)?\s*\(`, window)
	f := _finding(path, i, line, "libxmljs huge: true disables libxml2's entity-expansion and size limits; remove it for untrusted XML")
}
