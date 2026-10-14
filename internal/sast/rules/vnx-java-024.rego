package vulnetix.rules.vnx_java_024

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-024",
	"name": "Java XML entity expansion (Billion Laughs) — DTD not disabled",
	"description": "An XML parser factory is created and used without disabling DOCTYPE declarations or enabling secure processing, so a document with nested internal entity definitions can expand exponentially and exhaust memory and CPU (Billion Laughs). Reported: DocumentBuilderFactory.newInstance()/newDefaultInstance(), SAXParserFactory.newInstance(), dom4j new SAXReader() and JDOM new SAXBuilder() unless that same variable gets setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\" or a constant naming DOCTYPE, true) or setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) somewhere in the file; and XMLInputFactory.newInstance()/newFactory() unless it gets setProperty(XMLInputFactory.SUPPORT_DTD or \"javax.xml.stream.supportDTD\", false). A factory built and used in one chained expression is reported. Not reported: a factory passed to a harden/secure/configure helper, and the pattern in comments or string literals. setExpandEntityReferences(false), turning off external entities and ACCESS_EXTERNAL_DTD do not stop internal expansion and are not treated as mitigations; disabling the feature with false is not either. External entity resolution (XXE) is VNX-JAVA-004/VNX-JAVA-029's concern. Recent JDKs cap expansion at jdk.xml.entityExpansionLimit, which this rule does not assume.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-024/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [776],
	"capec": ["CAPEC-197"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xml", "xxe", "dos", "java"],
}

_strip_strings(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

_create := {
	"jaxp": `\b(DocumentBuilderFactory|SAXParserFactory)\s*\.\s*new(Default)?Instance\s*\(|\bnew\s+(SAXReader|SAXBuilder)\s*\(`,
	"stax": `\bXMLInputFactory\s*\.\s*new(Default)?(Instance|Factory)\s*\(`,
}

_assign := `([A-Za-z_]\w*)\s*=\s*(?:new\s+)?(?:[\w.]*\.)?(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|SAXBuilder)\b`

_mitigated(code, "jaxp", v) if {
	some m in regex.find_all_string_submatch_n(concat("", [`\b`, v, `\s*\.\s*setFeature\s*\(\s*([^,]+),\s*(?:true|Boolean\.TRUE)\s*\)`]), code, -1)
	regex.match(`disallow-doctype-decl|DOCTYPE|(?i:doctype)|FEATURE_SECURE_PROCESSING|secure-processing`, m[1])
}

_mitigated(code, "stax", v) if {
	regex.match(concat("", [`\b`, v, `\s*\.\s*setProperty\s*\(\s*(?:XMLInputFactory\s*\.\s*SUPPORT_DTD|"javax\.xml\.stream\.supportDTD")\s*,\s*(?:false|Boolean\.FALSE)\s*\)`]), code)
}

_mitigated(code, _, v) if {
	regex.match(concat("", [`(?i:\w*(harden|secur|safe|configure)\w*)\s*\(\s*`, v, `\s*\)`]), code)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|SAXBuilder`, content)
	lines := split(content, "\n")
	code := helpers.code_text(lines)
	some i, line in lines
	regex.match(`Factory|SAXReader|SAXBuilder`, line)
	not helpers.is_comment_line(line)
	sl := _strip_strings(line)
	some kind, re in _create
	regex.match(re, sl)
	_unhardened(code, kind, sl)
	finding := {
		"rule_id": metadata.id,
		"message": "XML parser factory allows DOCTYPE declarations, so nested entity definitions can expand exponentially (Billion Laughs); set feature 'http://apache.org/xml/features/disallow-doctype-decl' to true (or XMLInputFactory.SUPPORT_DTD to false)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Built and used without a variable: nothing can configure it.
_unhardened(_, _, sl) if not regex.match(_assign, sl)

_unhardened(code, kind, sl) if {
	some m in regex.find_all_string_submatch_n(_assign, sl, 1)
	not _mitigated(code, kind, m[1])
}
