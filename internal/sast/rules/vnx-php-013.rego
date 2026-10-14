package vulnetix.rules.vnx_php_013

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-013",
	"name": "PHP XXE via LIBXML_NOENT or LIBXML_DTDLOAD flag",
	"description": "An XML parser is told to expand entities or load external DTDs, which lets a document read local files (file:///etc/passwd) or make server-side requests through external entities (XXE). Reported: simplexml_load_string()/simplexml_load_file(), new SimpleXMLElement(), DOMDocument ->loadXML()/->load()/->loadHTML()/->loadHTMLFile() and XMLReader ->open()/->xml() called with LIBXML_NOENT or LIBXML_DTDLOAD, given inline, on the following lines of a call broken across lines, or through a variable assigned such flags within the 20 lines above; a DOMDocument ->substituteEntities or ->resolveExternals property set to true; XMLReader setParserProperty(XMLReader::SUBST_ENTITIES or XMLReader::LOADDTD, true); and libxml_disable_entity_loader(false), which re-enables the external entity loader on PHP before 8.0. Not reported: parsing with default options or with LIBXML_NONET/LIBXML_NOCDATA/LIBXML_NOERROR, a flag cleared with ~LIBXML_NOENT, the properties set to false, the flag name inside a string literal, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-013/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-221"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xxe", "xml", "php"],
}

_gate(content) if contains(content, "LIBXML_")

_gate(content) if contains(content, "Entit")

_gate(content) if contains(content, "resolveExternals")

_gate(content) if contains(content, "entity_loader")

_gate(content) if contains(content, "LOADDTD")

_call_re := `(?i)\b(simplexml_load_string|simplexml_load_file)\s*\(|\bnew\s+\\?SimpleXMLElement\s*\(|->(loadXML|load|loadHTML|loadHTMLFile|open|xml)\s*\(|\bXMLReader::(open|xml)\s*\(`

_flag_re := `\bLIBXML_(NOENT|DTDLOAD)\b`

_lit_re := `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

# Code text: literals emptied and cleared flags (~LIBXML_NOENT) removed.
_code(line) := regex.replace(regex.replace(line, _lit_re, `''`), `~\s*\(?\s*LIBXML_\w+`, "")

_call_text(lines, i) := t if {
	parts := regex.split(_call_re, _code(lines[i]))
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _continue(lines, i, rest)
}

_continue(lines, i, rest) := rest if contains(rest, ";")

_continue(lines, i, rest) := concat("\n", array.concat([rest], [_code(l) | some l in array.slice(lines, i + 1, min([count(lines), i + 5]))])) if {
	not contains(rest, ";")
}

_enables(lines, i) if {
	regex.match(_call_re, _code(lines[i]))
	t := _call_text(lines, i)
	regex.match(_flag_re, t)
}

# The flags travel in a variable assigned shortly above.
_enables(lines, i) if {
	regex.match(_call_re, _code(lines[i]))
	t := _call_text(lines, i)
	some m in regex.find_all_string_submatch_n(`\$(\w+)`, t, -1)
	v := m[1]
	some j in numbers.range(max([0, i - 20]), i - 1)
	j < i
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(concat("", [`^\s*\$`, v, `\s*\|?=[^=]`]), prev)
	regex.match(_flag_re, _code(prev))
}

_enables(lines, i) if regex.match(`->\s*(substituteEntities|resolveExternals)\s*=\s*(true|1)\b`, _code(lines[i]))

_enables(lines, i) if regex.match(`(?i)setParserProperty\s*\(\s*\\?XMLReader::(SUBST_ENTITIES|LOADDTD)\s*,\s*(true|1)\b`, _code(lines[i]))

_enables(lines, i) if regex.match(`(?i)\blibxml_disable_entity_loader\s*\(\s*(false|0)\s*\)`, _code(lines[i]))

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_enables(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "XXE: the XML parser is told to expand entities or load external DTDs; parse untrusted XML without LIBXML_NOENT/LIBXML_DTDLOAD and with entity substitution off",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
