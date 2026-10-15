# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_583

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-583",
	"name": "finalize() method declared public",
	"description": "A Java override of Object.finalize() declared public (any modifier order, with or without an annotation or throws clause on the same line), and a Kotlin member fun finalize() with no visibility modifier (Kotlin members default to public) or declared public. Object.finalize() is protected; widening it lets any caller run the finaliser, releasing native resources or other cleanup while the object is still in use. Not reported: a protected or package-private Java finalize(), a protected, private or internal Kotlin finalize(), a Kotlin top-level fun finalize(), an overload that takes parameters, methods whose name only starts with finalize, calls to finalize(), comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-583/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [583],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["finalize-public", "cwe-583"],
}

# Annotations, modifiers including public, `void finalize()` with no parameters.
_decl_re := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*((?:(?:public|protected|private|final|synchronized|native|strictfp)\s+)+)void\s+finalize\s*\(\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "finalize")
	regex.match(`(?m)\bpublic\b[^\n(]*\bvoid\s+finalize\s*\(\s*\)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "finalize")
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(m) > 0
	regex.match(`\bpublic\b`, m[0][1])
	finding := {
		"rule_id": metadata.id,
		"message": "finalize() is declared public: any caller can run the finaliser while the object is still in use. Declare it protected, as Object.finalize() is, or replace it with java.lang.ref.Cleaner",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Kotlin declares a finaliser as a member `fun finalize()` (no override);
# Kotlin's default visibility is public, so a member with no visibility
# modifier, or `public`, is reported. A top-level function (no indent) is not
# a finaliser.
_kt_re := `^[ \t]+(?:@[\w.]+(?:\([^)]*\))?\s+)*((?:(?:public|protected|private|internal|open|final|override)\s+)*)fun\s+finalize\s*\(\s*\)\s*(?::\s*Unit\s*)?(?:\{|=|$)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".kt")
	contains(content, "finalize")
	regex.match(`(?m)\bfun\s+finalize\s*\(\s*\)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "finalize")
	m := regex.find_all_string_submatch_n(_kt_re, line, 1)
	count(m) > 0
	not regex.match(`\b(?:protected|private|internal)\b`, m[0][1])
	finding := {
		"rule_id": metadata.id,
		"message": "finalize() has Kotlin's default public visibility: any caller can run the finaliser while the object is still in use. Declare it protected, or replace it with java.lang.ref.Cleaner",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
