# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_827

import rego.v1

metadata := {
	"id": "VNX-827",
	"name": "Improper Control of Document Type Definition",
	"description": "Reports XML parser configuration that explicitly turns on DOCTYPE/DTD processing, so a document can declare its own DTD (internal entities for Billion Laughs expansion, external DTD and parameter-entity references for XXE and out-of-band exfiltration). Java: setFeature(disallow-doctype-decl, false) (the URI or a constant whose name says DOCTYPE), setFeature(load-external-dtd, true), XMLInputFactory setProperty(SUPPORT_DTD / javax.xml.stream.supportDTD, true or Boolean.TRUE), and setAttribute/setProperty(ACCESS_EXTERNAL_DTD, \"all\" or a protocol list), including a call whose arguments continue on the next lines. C#: DtdProcessing = DtdProcessing.Parse (assignment or object initialiser) and ProhibitDtd = false. Python: lxml XMLParser(load_dtd=True), XMLParser(dtd_validation=True) or XMLParser(attribute_defaults=True), with arguments up to six lines below. PHP: the LIBXML_DTDLOAD, LIBXML_DTDATTR and LIBXML_DTDVALID flags, $dom->resolveExternals = true, libxml_disable_entity_loader(false) and XMLReader setParserProperty(XMLReader::LOADDTD, VALIDATE or DEFAULTATTRS, true). Ruby: Nokogiri config.dtdload / config.dtdvalid and ParseOptions::DTDLOAD/DTDVALID/DTDATTR, libxml-ruby Parser::Options::DTDLOAD and XML.default_load_external_dtd = true. Not reported: the same settings switched off (disallow-doctype-decl true, SUPPORT_DTD false, ACCESS_EXTERNAL_DTD \"\", DtdProcessing.Prohibit/Ignore, ProhibitDtd = true, load_dtd=False, nodtdload), the dtdload? / dtdvalid? predicates, comparisons (== DtdProcessing.Parse), unrelated features, factories left at their defaults (VNX-JAVA-004/VNX-JAVA-029 judge unhardened Java factories), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-827/",
	"languages": ["java", "csharp", "python", "php", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [827],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["improper-control-of-document-type-definition", "cwe-827", "xml", "dtd", "xxe"],
}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, line)

_strip_c(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

_strip_script(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `\s#.*$|//.*$`, "")

_join(lines, i, k) := concat(" ", array.slice(lines, i, min([i + k, count(lines)])))

# ---- Java ----------------------------------------------------------------

_java_res := [
	`^\s*\.?\s*setFeature\s*\(\s*(?:"[^"]*disallow-doctype-decl"|[\w.]*(?i:doctype)\w*)\s*,\s*(?:false|Boolean\.FALSE)\s*\)`,
	`^\s*\.?\s*setFeature\s*\(\s*(?:"[^"]*load-external-dtd"|[\w.]*(?i:external_?dtd)\w*)\s*,\s*(?:true|Boolean\.TRUE)\s*\)`,
	`^\s*\.?\s*setProperty\s*\(\s*(?:(?:XMLInputFactory\.)?SUPPORT_DTD|"javax\.xml\.stream\.supportDTD")\s*,\s*(?:true|Boolean\.TRUE)\s*\)`,
	`^\s*\.?\s*set(?:Attribute|Property)\s*\(\s*(?:(?:[\w.]*XMLConstants\.)?ACCESS_EXTERNAL_DTD|"http://javax\.xml\.XMLConstants/property/accessExternalDTD")\s*,\s*"[^"\s]+"\s*\)`,
]

_java_hit(lines, i, line) if {
	code := _strip_c(line)
	regex.match(`\.set(?:Feature|Property|Attribute)\s*\(`, code)
	text := _join(lines, i, 4)
	some call in regex.find_all_string_submatch_n(`\.set(?:Feature|Property|Attribute)\s*\(.*`, text, -1)
	some re in _java_res
	regex.match(re, trim_prefix(call[0], "."))
}

# ---- C# ------------------------------------------------------------------

_cs_hit(_, _, line) if {
	code := _strip_c(line)
	regex.match(`\bDtdProcessing\s*=\s*(?:System\.Xml\.)?DtdProcessing\.Parse\b|\bProhibitDtd\s*=\s*false\b`, code)
}

# ---- Python --------------------------------------------------------------

_py_hit(lines, i, line) if {
	code := _strip_script(line)
	regex.match(`\bXMLParser\s*\(`, code)
	text := _strip_script(_join(lines, i, 6))
	regex.match(`\bXMLParser\s*\([^)]*\b(?:load_dtd|dtd_validation|attribute_defaults)\s*=\s*True\b`, text)
}

# ---- PHP -----------------------------------------------------------------

_php_hit(_, _, line) if {
	code := _strip_script(line)
	regex.match(`\bLIBXML_DTD(?:LOAD|ATTR|VALID)\b|->\s*resolveExternals\s*=\s*true\b|\blibxml_disable_entity_loader\s*\(\s*false\s*\)|\bsetParserProperty\s*\(\s*\\?XMLReader::(?:LOADDTD|VALIDATE|DEFAULTATTRS)\s*,\s*true\s*\)`, code)
}

# ---- Ruby ----------------------------------------------------------------

_rb_hit(_, _, line) if {
	code := _strip_script(line)
	regex.match(`\.dtd(?:load|valid)(?:[^\w?!=]|$)|\b(?:Parse)?Options::DTD(?:LOAD|VALID|ATTR)\b|\bdefault_load_external_dtd\s*=\s*true\b`, code)
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "cs" if endswith(path, ".cs")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "rb" if endswith(path, ".rb")

_gate := {
	"java": `disallow-doctype-decl|(?i:doctype)|load-external-dtd|(?i:external_?dtd)|SUPPORT_DTD|supportDTD|ACCESS_EXTERNAL_DTD|accessExternalDTD`,
	"cs": `DtdProcessing\.Parse|ProhibitDtd`,
	"py": `load_dtd|dtd_validation|attribute_defaults`,
	"php": `LIBXML_DTD|resolveExternals|libxml_disable_entity_loader|XMLReader::(?:LOADDTD|VALIDATE|DEFAULTATTRS)`,
	"rb": `dtdload|dtdvalid|DTDLOAD|DTDVALID|DTDATTR`,
}

_hit("java", lines, i, line) if _java_hit(lines, i, line)

_hit("cs", lines, i, line) if _cs_hit(lines, i, line)

_hit("py", lines, i, line) if _py_hit(lines, i, line)

_hit("php", lines, i, line) if _php_hit(lines, i, line)

_hit("rb", lines, i, line) if _rb_hit(lines, i, line)

_words := {
	"java": {"DTD", "octype", "OCTYPE", "dtd"},
	"cs": {"DtdProcessing", "ProhibitDtd"},
	"py": {"_dtd", "dtd_", "attribute_defaults"},
	"php": {"LIBXML_DTD", "resolveExternals", "libxml_disable_entity_loader", "setParserProperty"},
	"rb": {"dtd", "DTD"},
}

_has_word(lang, content) if {
	some w in _words[lang]
	contains(content, w)
}

_hint :=`(?i)dtd|doctype`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_word(lang, content)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	_line_candidate(lang, lines, i, line)
	not _is_comment(line)
	_hit(lang, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "The XML parser is configured to process DOCTYPE declarations or load DTDs; a document can then define its own entities (Billion Laughs) or pull an external DTD (XXE). Leave DTD processing disabled (disallow-doctype-decl true, SUPPORT_DTD false, DtdProcessing.Prohibit, load_dtd=False)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Cheap per-line filter: the line itself names DTD/DOCTYPE, or (Java and
# Python) opens a call whose arguments continue below.
_line_candidate(_, _, _, line) if regex.match(_hint, line)

_line_candidate("java", _, _, line) if regex.match(`\.set(?:Feature|Property|Attribute)\s*\(\s*$`, line)

_line_candidate("py", _, _, line) if contains(line, "XMLParser(")

_line_candidate("php", _, _, line) if regex.match(`resolveExternals|libxml_disable_entity_loader|setParserProperty`, line)
