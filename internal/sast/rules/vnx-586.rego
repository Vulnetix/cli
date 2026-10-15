# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_586

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-586",
	"name": "Explicit Call to Finalize()",
	"description": "A Java call to finalize() with no arguments on any receiver (obj.finalize(), this.finalize(), getX().finalize(), a .finalize() continuing a call chain on the next line) or as a bare finalize(); statement. Finalisers are meant to be run once by the garbage collector; calling one directly runs the cleanup while the object is still reachable and again when it is collected. Not reported: super.finalize() (the correct chaining inside an overriding finalizer), declarations of finalize(), finalize(...) overloads with arguments, methods whose name only starts with finalize, System.runFinalization(), comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-586/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [586],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["object-finalize", "cwe-586"],
}

# The line with string literals blanked, so "obj.finalize()" in a message does
# not count.
_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# A receiver call: <expr>.finalize() where the receiver is not `super`.
_call(c) if {
	ms := regex.find_all_string_submatch_n(`(\w*)\s*\)?\s*\.\s*finalize\s*\(\s*\)`, c, -1)
	some m in ms
	m[1] != "super"
}

# The call chain continues from the previous line: `.finalize();`.
_call(c) if regex.match(`^\s*\.\s*finalize\s*\(\s*\)`, c)

# A bare statement `finalize();`.
_call(c) if regex.match(`^\s*finalize\s*\(\s*\)\s*;`, c)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "finalize")
	regex.match(`(?m)finalize\s*\(\s*\)\s*[;),.]`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "finalize")
	not helpers.is_comment_line(line)
	_call(_code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Explicit call to finalize(): the garbage collector runs finalizers; calling one directly releases resources while the object is still in use. Use close() or a java.lang.ref.Cleaner",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
