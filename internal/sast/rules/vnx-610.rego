# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_610

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-610",
	"name": "Externally Controlled Reference to a Resource in Another Sphere (XML external references enabled)",
	"description": "CWE-610 is a class (external entities, XInclude, external DTDs and schemas are all references a document makes to resources outside the parser's sphere); this rule reports its most concrete Java form, a call that explicitly turns such references on: setFeature(external-general-entities / external-parameter-entities / load-external-dtd, true), setFeature(disallow-doctype-decl, false), setFeature(FEATURE_SECURE_PROCESSING, false), setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES / javax.xml.stream.isSupportingExternalEntities, true), setAttribute/setProperty(ACCESS_EXTERNAL_DTD / ACCESS_EXTERNAL_SCHEMA / ACCESS_EXTERNAL_STYLESHEET, \"all\" or a protocol list such as \"file,http\"), and setXIncludeAware(true), including a call whose arguments continue on the next lines (also after a chained getXMLReader()), a setFeature(CONSTANT, true) whose String constant in the same file holds one of those feature URLs, and System.setProperty(javax.xml.accessExternalDTD or accessExternalSchema, \"all\" or a protocol list). Not reported: the same calls switching the feature off (false, \"\"), feature names held in variables or constants of another file, unrelated features (namespaces, validation), a factory left at its defaults (VNX-JAVA-004 and VNX-JAVA-029 judge unhardened factories), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-610/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [610],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["external-entity", "xml", "cwe-610"],
}

_enables := [
	`(?:external-general-entities|external-parameter-entities|load-external-dtd)"\s*,\s*(?:true|Boolean\.TRUE)\s*\)`,
	`disallow-doctype-decl"\s*,\s*(?:false|Boolean\.FALSE)\s*\)`,
	`FEATURE_SECURE_PROCESSING\s*,\s*(?:false|Boolean\.FALSE)\s*\)`,
	`(?:IS_SUPPORTING_EXTERNAL_ENTITIES|isSupportingExternalEntities")\s*,\s*(?:true|Boolean\.TRUE)\s*\)`,
	`(?:ACCESS_EXTERNAL_(?:DTD|SCHEMA|STYLESHEET)|accessExternal(?:DTD|Schema|Stylesheet)")\s*,\s*"(?:all|[a-z,]*(?:file|https?|jar|ftp|jrt)[a-z,]*)"\s*\)`,
	`\.setXIncludeAware\s*\(\s*(?:true|Boolean\.TRUE)\s*\)`,
]

_strip(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# The call's text: this line and, when its argument list is not closed here,
# the next two.
_stmt(lines, i) := lines[i] if _closed(lines[i])

_stmt(lines, i) := s if {
	not _closed(lines[i])
	end := min([count(lines) - 1, i + 2])
	s := concat(" ", [lines[k] | some k in numbers.range(i, end)])
}

# The .setX( call's own argument list closes on this line (a getXMLReader()
# earlier on the line does not count).
_closed(line) if {
	m := regex.find_all_string_submatch_n(`\.set(?:Feature|Property|Attribute|XIncludeAware)\s*\((.*)$`, _strip(line), 1)
	rest := m[0][1]
	count(regex.find_all_string_submatch_n(`\)`, rest, -1)) > count(regex.find_all_string_submatch_n(`\(`, rest, -1))
}

_feature_url := `(?:external-general-entities|external-parameter-entities|load-external-dtd)"`

# Names of String constants holding one of the dangerous feature URLs, with
# the literal on the declaration line or the next.
_feature_consts(lines) := {n |
	some k, l in lines
	contains(l, "String")
	m := regex.find_all_string_submatch_n(`\bString\s+([A-Za-z_]\w*)\s*=\s*(.*)$`, l, 1)
	n := m[0][1]
	val := concat(" ", [m[0][2], _next_line(lines, k)])
	regex.match(concat("", [`^\s*"[^"]*`, _feature_url]), val)
}

_next_line(lines, k) := lines[k + 1] if k + 1 < count(lines)

_next_line(lines, k) := "" if k + 1 >= count(lines)

# setFeature(CONSTANT, true) where the constant names an external-reference
# feature declared in the same file.
_const_enables(lines, stmt) if {
	m := regex.find_all_string_submatch_n(`\.setFeature\s*\(\s*(?:\w+\.)?([A-Za-z_]\w*)\s*,\s*(?:true|Boolean\.TRUE)\s*\)`, stmt, 1)
	m[0][1] in _feature_consts(lines)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`external-|disallow-doctype-decl|FEATURE_SECURE_PROCESSING|SupportingExternalEntities|SUPPORTING_EXTERNAL_ENTITIES|ACCESS_EXTERNAL_|accessExternal|setXIncludeAware`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".set")
	not helpers.is_comment_line(line)
	regex.match(`\.set(?:Feature|Property|Attribute|XIncludeAware)\s*\(`, _strip(line))
	stmt := _stmt(lines, i)
	_enables_any(lines, stmt)
	finding := {
		"rule_id": metadata.id,
		"message": "XML parser explicitly allowed to resolve external references (entities, DTDs, schemas, XInclude): a document can make it read local files or fetch URLs. Turn the feature off",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_enables_any(lines, stmt) if {
	some re in _enables
	regex.match(re, stmt)
}

_enables_any(lines, stmt) if _const_enables(lines, stmt)
