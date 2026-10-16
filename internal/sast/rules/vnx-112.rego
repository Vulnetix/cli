# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_112

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-112",
	"name": "Missing XML Validation",
	"description": "An XML document received in an HTTP request is parsed and used with no schema or structural validation anywhere in the file, so the application trusts whatever element structure, types and cardinality the requester sends (CWE-112). Reported: Java DocumentBuilder/SAXParser/XMLReader .parse, JAXB .unmarshal and StAX createXMLStreamReader/createXMLEventReader (in a file importing javax.xml, org.xml.sax or JAXB); Python lxml/ElementTree/cElementTree/defusedxml fromstring/XML/parse, minidom/pulldom parseString/parse, xmltodict.parse, objectify and untangle; Node xml2js parseString/parseStringPromise (also destructured imports), libxmljs parseXml/parseXmlString, DOMParser parseFromString, xml-js xml2js/xml2json, and fast-xml-parser XMLParser .parse. The parsed argument must be the request body or a request value (Java getInputStream/getReader/getParameter or an @RequestBody parameter; Python request.data/body/get_data/stream/files/form/args/values/json/GET/POST; Node req/request body/query/params or Koa ctx.request.body), inline or through a variable assigned from it (or from such a variable) in the 25 lines above. Not reported: a file that mentions schema validation or a validator in code (setSchema, SchemaFactory/newSchema, Validator, .validate(, setValidating(true), XMLSchema/xmlschema, assertValid, RelaxNG, schema=, an XSD, or a Joi/ajv/pydantic-style schema check of the parsed result), XML read from files or constants, Java .parse calls on a static receiver or one named for dates, formats, URIs, numbers or JSON (LocalDate.parse, sdf.parse, JSON.parse), and calls in comments. XXE (external entity) processing is a different weakness, reported by the XXE rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-112/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [112],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xml", "validation", "schema", "cwe-112"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

# The file uses an XML parser at all.
_xml_gate := {
	"java": `javax\.xml|org\.xml\.sax|JAXBContext`,
	"py": `etree|ElementTree|minidom|pulldom|xmltodict|objectify|untangle`,
	"js": `xml2js|libxmljs|DOMParser|XMLParser|xml-js|parseXml`,
}

_src := {
	"java": `\.getInputStream\s*\(|\.getReader\s*\(|\.getParameter\s*\(|@RequestBody\b`,
	"py": `\brequest\.(?:data|body|get_data|stream|files|form|args|values|json|get_json|GET|POST)\b`,
	"js": `\b(?:req|request)\.(?:body|query|params|rawBody|files?)\b|\bctx\.request\.body\b|\bfile\.buffer\b`,
}

_sinks := {
	"java": [
		`\.(?:parse|unmarshal|createXMLStreamReader|createXMLEventReader)\s*\((.*)$`,
	],
	"py": [
		`\b(?:etree|ET|ElementTree|cElementTree|objectify|defusedxml\.\w+|DET|SafeET)\.(?:fromstring|XML|parse|fromstringlist)\s*\((.*)$`,
		`\b(?:minidom|pulldom|xmltodict|untangle)\.(?:parseString|parse)\s*\((.*)$`,
	],
	"js": [
		`(?:\bxml2js\.|\.|(?:^|[^\w]))parseString(?:Promise)?\s*\((.*)$`,
		`(?:\blibxmljs\d?\.|^|[^\w.])parseXml(?:String)?\s*\((.*)$`,
		`\.parseFromString\s*\((.*)$`,
		`\b(?:convert\.)?xml2(?:js|json)\s*\((.*)$`,
	],
}

# fast-xml-parser: parser.parse(...) only where an XMLParser is constructed.
_fxp_sink := `\.parse\s*\((.*)$`

# Java .parse( is also LocalDate.parse, Integer.parse..., sdf.parse and
# JSON.parse. XML parsers are instances (db.parse, parser.parse,
# newDocumentBuilder().parse), so a capitalised (static) receiver, or one
# named for dates, formats, URIs or JSON, is not an XML parse.
_non_xml_receiver("java", code) if {
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*|\))\s*\.(?:parse|unmarshal|createXMLStreamReader|createXMLEventReader)\s*\(`, code, 1)
	_static_or_non_xml(m[1])
}

_static_or_non_xml(r) if regex.match(`^[A-Z]\w*[a-z]`, r)

_static_or_non_xml(r) if regex.match(`(?i)format|fmt|json|mapper|gson|date|time|uri|url|number`, r)

# Validation in code anywhere in the file.
_validated(text) if regex.match(`(?i)schema|\.xsd\b|\bxsd\b|\.validate\s*\(|validator|assertvalid|relaxng|setvalidating\s*\(\s*true`, text)

_assign_re := `^\s*(?:(?:final|var|let|const|val)\s+)?(?:[A-Za-z_][\w<>\[\]\.?]*\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]\|\. ]+?\s*)?=[^=>]`

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(_assign_re, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{\s*([A-Za-z_]\w*)`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_params(line) := {m[1] |
	some m in regex.find_all_string_submatch_n(`@RequestBody\b(?:\s*\([^)]*\))?\s+(?:final\s+)?(?:String|byte\[\]|InputStream|Reader)\s+(\w+)`, line, -1)
}

_t1(lang, lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	regex.match(_src[lang], l)
	not helpers.is_comment_line(l)
	v := _assigned(l)
} | {v |
	lang == "java"
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	some v in _params(lines[j])
}

_t2(lines, i, n1) := {v |
	i > 0
	count(n1) > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	v := _assigned(l)
	not v in n1
	some n in n1
	regex.match(concat("", [`=.*\b`, n, `\b`]), l)
	not helpers.is_comment_line(l)
}

_tainted(lang, lines, i, arg) if regex.match(_src[lang], arg)

_tainted(lang, lines, i, arg) if {
	not regex.match(_src[lang], arg)
	n1 := _t1(lang, lines, i)
	some n in n1 | _t2(lines, i, n1)
	regex.match(concat("", [`\b`, n, `\b`]), arg)
}

_strip_lits(s) := regex.replace(regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

_args(lines, i, rest) := rest if trim_space(rest) != ""

_args(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_depth(s) := ((strings.count(s, "(") + strings.count(s, "[")) + strings.count(s, "{")) - ((strings.count(s, ")") + strings.count(s, "]")) + strings.count(s, "}"))

_close_positions(s) := [k |
	some k in indexof_n(s, ")")
	_depth(substring(s, 0, k)) == 0
]

_call_args(s) := substring(s, 0, min(ends)) if {
	ends := _close_positions(s)
	count(ends) > 0
}

_call_args(s) := s if count(_close_positions(s)) == 0

_sink_res(lang, content) := _sinks[lang] if lang != "js"

_sink_res("js", content) := array.concat(_sinks.js, [_fxp_sink]) if contains(content, "XMLParser")

_sink_res("js", content) := _sinks.js if not contains(content, "XMLParser")

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_xml_gate[lang], content)
	regex.match(concat("", ["(?m)", _src[lang]]), content)
	lines := split(content, "\n")
	not _validated(helpers.code_text(lines))
	sink_res := _sink_res(lang, content)
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	code := _strip_lits(line)
	some re in sink_res
	regex.match(re, code)
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	not _non_xml_receiver(lang, code)
	arg := _call_args(_args(lines, i, m[0][1]))
	_tainted(lang, lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "XML from the request is parsed and used without schema validation; validate it against an XSD (setSchema / XMLSchema / libxmljs validate) or check the parsed structure with a schema before using it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
