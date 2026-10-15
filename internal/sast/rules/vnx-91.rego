# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_91

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-91",
	"name": "XML Injection",
	"description": "An XML document is assembled as text with an HTTP request value inside it, so a value containing </name><role>admin</role> or a CDATA/entity sequence changes the document's structure. Reported: a line holding a string literal with an XML tag (<name>, </user>, <?xml, soap:Envelope) that splices in a request value by concatenation (+, PHP .), interpolation (f-strings, template literals, Ruby #{}, PHP \"$x\"/{$x}), %-formatting, str.format or fmt.Sprintf, in a file that works with XML (an <?xml declaration, an XML/SOAP content type, or an XML parser or library such as DocumentBuilder, SAXParser, JAXB, lxml/etree/minidom, xml2js/DOMParser/fast-xml-parser, simplexml/DOMDocument/SoapClient, encoding/xml, Nokogiri/REXML). Request values: Go r.FormValue/URL.Query()/Header.Get and gin/echo c.Query/c.Param/c.PostForm; Java getParameter/getHeader; Python request.args/form/values/json/GET/POST/data; Express req.body/query/params/headers/cookies; PHP $_GET/$_POST/$_REQUEST/$_COOKIE; Rails params; directly or through a variable assigned from one in the 15 lines above. Not reported: values passed through an XML/HTML escaper (escape, quoteattr, StringEscapeUtils.escapeXml*, htmlspecialchars, html.EscapeString, xml.EscapeText, CGI.escapeHTML, encode*), documents built with a DOM/ElementTree/builder API, markup built in files that never touch XML (HTML output is the XSS rules' concern), constant documents, comments. XPath query injection is VNX-643/VNX-JAVA-013.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-91/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [91],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["xml-injection", "injection", "cwe-91"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

# The file works with XML at all.
_xml_needles := {
	"go": {"encoding/xml", "text/xml", "application/xml", "<?xml", "soap"},
	"py": {"etree", "minidom", "lxml", "xml.dom", "xml.sax", "xmltodict", "text/xml", "application/xml", "<?xml", "soap", "zeep"},
	"java": {"DocumentBuilder", "SAXParser", "XMLReader", "XMLStreamReader", "JAXB", "Unmarshaller", "SOAPMessage", "text/xml", "application/xml", "<?xml", "soap"},
	"js": {"xml2js", "libxmljs", "DOMParser", "parseFromString", "fast-xml-parser", "xmldom", "xmlbuilder", "text/xml", "application/xml", "<?xml", "soap"},
	"php": {"simplexml", "DOMDocument", "loadXML", "XMLReader", "SoapClient", "text/xml", "application/xml", "<?xml", "soap"},
	"rb": {"Nokogiri", "REXML", "Builder::XmlMarkup", "Ox.", "text/xml", "application/xml", "<?xml", "soap"},
}

_source := {
	"go": `\b(r|req|request)\.(FormValue|PostFormValue|URL\.Query\(\)|Header\.Get|PathValue|Form\.Get|PostForm\.Get)|\bc\.(Query|DefaultQuery|Param|PostForm|DefaultPostForm|FormValue|QueryParam|GetHeader)\s*\(`,
	"py": `\brequest\.(args|form|values|json|get_json|GET|POST|data|body|query_params|headers|cookies)\b`,
	"java": `\.(getParameter|getParameterValues|getHeader)\s*\(`,
	"js": `\b(req|request)\.(body|query|params|headers|cookies)\b|\bctx\.(query|params|request\.body)\b`,
	"php": `\$_(GET|POST|REQUEST|COOKIE)\b`,
	"rb": `\bparams\s*(\[|\.(fetch|require|permit|dig)\b)|\brequest\.(params|body|query_parameters|request_parameters)\b|\bcookies\s*\[`,
}

_source_needles := {
	"go": {"r.", "req.", "request.", "c."},
	"py": {"request."},
	"java": {"getParameter", "getHeader"},
	"js": {"req.", "request.", "ctx."},
	"php": {"$_"},
	"rb": {"params", "request.", "cookies["},
}

# A string literal holding an XML tag.
_tag_literal := `["'\x60][^"'\x60]*(<\??[A-Za-z][\w:.-]*(\s[^<>"'\x60]*)?/?>|</[A-Za-z][\w:.-]*>)`

# Text is spliced into the literal rather than handed to a builder.
_splice := {
	"go": `\+|\bfmt\.Sprintf\s*\(`,
	"py": `\+|\bf["']|%\s*[\w(]|\.format\s*\(`,
	"java": `\+|String\.format\s*\(|\.formatted\s*\(`,
	"js": `\+|\$\{`,
	"php": `\.|"[^"]*\$\w|\{\$`,
	"rb": `\+|#\{|<<|%\s*[\[(]`,
}

_escaped := `(?i)escape|quoteattr|htmlspecialchars|htmlentities|xml_?encode|encode(xml|html|uri|forxml)|EscapeText|EscapeString|sanitiz|\bh\(|ERB::Util|\bcdata`

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_assigned(lang, line) := concat("", [`\$`, m[0][1], `\b`]) if {
	lang == "php"
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, line, 1)
	count(m) > 0
}

_assigned(lang, line) := concat("", [`\b`, v, `\b`]) if {
	lang != "php"
	not _destructure(lang, line)
	v := helpers.assigned_first(line)
}

# JavaScript destructuring: const { username, pw: password } = req.body
_destructure(lang, line) := names if {
	lang == "js"
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=[^=]`, line, 1)
	count(m) > 0
	parts := [n |
		some p in split(m[0][1], ",")
		seg := split(p, ":")
		n := trim_space(regex.replace(seg[count(seg) - 1], `=.*$`, ""))
		regex.match(`^\w+$`, n)
	]
	count(parts) > 0
	names := concat("|", parts)
}

_assigned(lang, line) := concat("", [`\b(`, names, `)\b`]) if {
	names := _destructure(lang, line)
}

_injected(lang, _, _, line) if regex.match(_source[lang], line)

_injected(lang, lines, i, line) if {
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_source[lang], prev)
	not regex.match(_escaped, prev)
	re := _assigned(lang, prev)
	regex.match(re, _outside_tags(line))
}

# The line with its XML tags removed, so a variable named like a tag
# (<name> beside name) is matched only where it is code.
_outside_tags(line) := regex.replace(line, `</?[A-Za-z][\w:.-]*>`, "")

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _xml_needles[lang])
	_has_any(content, _source_needles[lang])
	contains(content, "<")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "<")
	not helpers.is_comment_line(line)
	regex.match(_tag_literal, line)
	regex.match(_splice[lang], line)
	not regex.match(_escaped, line)
	_injected(lang, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "An XML document is built as text with a request value spliced in. A value such as </name><role>admin</role> or an entity/CDATA sequence rewrites the document the parser or the receiving service sees. Build the document with a DOM/ElementTree/builder API that sets text content, or XML-escape the value (& < > \" ') before inserting it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
