# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_112

import rego.v1

metadata := {
	"id": "VNX-112",
	"name": "Missing XML Validation",
	"description": "Detects source patterns associated with CWE-112 (Missing XML Validation). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-112/",
	"languages": ["java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [112],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["xml", "validation", "schema", "cwe-112"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".min.html")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
_is_comment_line(line) if startswith(trim_space(line), "--")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	content := input.file_contents[path]
	not contains(content, "setSchema(")
	not contains(content, "setValidating(true)")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"DocumentBuilderFactory.newInstance(", "SAXParserFactory.newInstance("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Java XML parser constructed without schema validation — set schema or setValidating(true) to prevent malformed XML processing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	content := input.file_contents[path]
	not contains(content, "XMLSchema")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"xml.etree.ElementTree.parse(", "etree.parse("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Python XML parsed without schema validation; validate against an XSD to prevent malformed input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	content := input.file_contents[path]
	not contains(content, "validate")
	not contains(content, "schema")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"xml2js.parseString(", "libxmljs.parseXml("}
	contains(line, _pat)
	finding := {
		"rule_id": metadata.id,
		"message": "Node XML parsed without schema validation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
