package vulnetix.rules.vnx_java_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-004",
	"name": "XML external entity (XXE) injection",
	"description": "Reports a Java XML parser factory created without XXE hardening: DocumentBuilderFactory, SAXParserFactory, XMLInputFactory (newInstance/newDefaultInstance/newFactory), XMLReaderFactory.createXMLReader, dom4j SAXReader and JDOM SAXBuilder, plus TransformerFactory in a file that loads a StreamSource/SAXSource stylesheet or document and SchemaFactory in a file that calls newSchema. A factory counts as hardened when, within the 40 lines after it is created and not only inside an if/else branch, the factory variable sets disallow-doctype-decl true, external-general/parameter-entities or load-external-dtd false, ACCESS_EXTERNAL_DTD/SCHEMA/STYLESHEET to \"\", FEATURE_SECURE_PROCESSING true, or (StAX) SUPPORT_DTD / IS_SUPPORTING_EXTERNAL_ENTITIES false, or when it is handed to a helper method in a file that applies such hardening. Also reports a line that explicitly re-enables entities (disallow-doctype-decl false, external-general-entities true, IS_SUPPORTING_EXTERNAL_ENTITIES true). Not reported: a TransformerFactory used only to serialise an in-memory DOM, JAXB contexts, factory names in comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-004/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-201"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xxe", "xml", "injection", "ssrf"],
}

_strip(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`)

_factory_re := `\b(?:(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.(?:newInstance|newDefaultInstance|newFactory|newDefaultFactory)|XMLReaderFactory\.(createXMLReader)|new\s+(SAXReader|SAXBuilder))\s*\(`

_hard_re := `(?i)disallow-doctype-decl"\s*,\s*true|external-(?:general|parameter)-entities"\s*,\s*false|load-external-dtd"\s*,\s*false|ACCESS_EXTERNAL_(?:DTD|SCHEMA|STYLESHEET)\s*,\s*""|accessExternal(?:DTD|Schema|Stylesheet)"\s*,\s*""|FEATURE_SECURE_PROCESSING\s*,\s*(?:true|Boolean\.TRUE)|secure-processing"\s*,\s*true|SUPPORT_DTD\s*,\s*(?:false|Boolean\.FALSE)|supportDTD"\s*,\s*(?:false|Boolean\.FALSE)|IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*(?:false|Boolean\.FALSE)|isSupportingExternalEntities"\s*,\s*(?:false|Boolean\.FALSE)`

_weaken_re := `(?i)disallow-doctype-decl"\s*,\s*false|external-general-entities"\s*,\s*true|IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*(?:true|Boolean\.TRUE)|isSupportingExternalEntities"\s*,\s*(?:true|Boolean\.TRUE)`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_kind(m) := concat("", [m[1], m[2], m[3]])

# TransformerFactory parses XML only when it is given a source to load;
# SchemaFactory only when it compiles a schema.
_relevant(_, k) if not k in {"TransformerFactory", "SchemaFactory"}

_relevant(content, "TransformerFactory") if regex.match(`new\s+(?:StreamSource|SAXSource)\s*\(`, content)

_relevant(content, "SchemaFactory") if contains(content, "newSchema(")

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`Factory\.new|XMLReaderFactory|SAXReader|SAXBuilder`, content)
	lines := split(content, "\n")
	file_hard := [k | some k, l in lines; regex.match(_hard_re, l); not helpers.is_comment_line(l)]
	some i, line in lines
	regex.match(`Factory\.|SAXReader|SAXBuilder`, line)
	not helpers.is_comment_line(line)
	sline := _strip(line)
	m := regex.find_all_string_submatch_n(_factory_re, sline, 1)
	count(m) > 0
	_relevant(content, _kind(m[0]))
	not _hardened(lines, i, sline, file_hard)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is created without disabling DTDs or external entities; set disallow-doctype-decl to true (or the StAX equivalents) before parsing untrusted XML", [_kind(m[0])]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_weaken_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_weaken_re, line)
	not helpers.is_comment_line(line)
	regex.match(`\.(?:setFeature|setProperty)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "XML parser explicitly re-enables DTDs or external entities; remove this setting",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_var(sline) := v if {
	mm := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:\([\w.]+\)\s*)?(?:[\w.]+\.(?:newInstance|newDefaultInstance|newFactory|newDefaultFactory|createXMLReader)|new\s+(?:SAXReader|SAXBuilder))\s*\(`, sline, 1)
	count(mm) > 0
	v := mm[0][1]
}

# The factory variable is configured on an unconditional line below.
_hardened(lines, i, sline, _) if {
	v := _var(sline)
	re := concat("", [`\b`, v, `\s*\.\s*set\w*\s*\(`])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 40]))
	contains(lines[k], v)
	regex.match(re, lines[k])
	regex.match(_hard_re, lines[k])
	not _conditional(lines, i, k)
}

# The factory is passed to a helper, and the file hardens a factory.
_hardened(lines, i, sline, file_hard) if {
	v := _var(sline)
	count(file_hard) > 0
	re := concat("", [`\w\s*\(\s*(?:[\w.]+\s*,\s*)*`, v, `\s*[,)]`])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 40]))
	contains(lines[k], v)
	regex.match(re, lines[k])
	not regex.match(concat("", [`\b`, v, `\s*\.`]), lines[k])
}

# Line k sits inside an if/else opened after the factory (line i).
_conditional(lines, i, k) if {
	ik := _indent(lines[k])
	i + 1 <= k - 1
	some m in numbers.range(i + 1, k - 1)
	regex.match(`^\s*(?:if\s*\(|\}?\s*else\b)`, lines[m])
	im := _indent(lines[m])
	im < ik
	not _closed(lines, m, k, im)
}

_closed(lines, m, k, im) if {
	m + 1 <= k - 1
	some x in numbers.range(m + 1, k - 1)
	_indent(lines[x]) <= im
	startswith(trim_left(lines[x], " \t"), "}")
}
