# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_578

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-578",
	"name": "EJB Bad Practices: Use of Class Loader",
	"description": "An Enterprise JavaBean obtains, creates, replaces or defines classes with a class loader, which the EJB specification forbids because it breaks the container's isolation and security model: the bean can load code the container never vetted or reach classes of other applications. A class counts as an EJB when its file imports javax.ejb or jakarta.ejb and declares @Stateless, @Stateful, @Singleton or @MessageDriven, or implements SessionBean, EntityBean or MessageDrivenBean. Reported in such a file: new URLClassLoader(...) or any new ...ClassLoader(...), instantiating a ClassLoader subclass declared in the file, getClassLoader(), Thread getContextClassLoader()/setContextClassLoader(...), ClassLoader.getSystemClassLoader()/getPlatformClassLoader(), and defineClass/defineHiddenClass calls. Not reported: the same calls in Spring beans, servlets and other non-EJB classes, Class.forName, a ClassLoader subclass declaration that is never instantiated, test code, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-578/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [578],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["ejb", "classloader", "cwe-578"],
}

_ejb_re := `@(?:Stateless|Stateful|Singleton|MessageDriven)\b|\bimplements\b[^{]*\b(?:SessionBean|EntityBean|MessageDrivenBean)\b`

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `//.*$`, "")

_sink_re := `\bnew\s+(?:\w+\.)*\w*ClassLoader\s*\(|(?:^|[^\w])getClassLoader\s*\(\s*\)|\b(?:get|set)ContextClassLoader\s*\(|\bClassLoader\s*\.\s*get(?:System|Platform)ClassLoader\s*\(|(?:^|[^\w])define(?:Hidden)?Class\s*\(`

# A method declaration, not a call: `Class<?> defineClass(String n, byte[] b) {`.
_declaration(c) if regex.match(`[\w>\]]\s+define(?:Hidden)?Class\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*$`, c)

_hit(c, _) if {
	regex.match(_sink_re, c)
	not _declaration(c)
}

_hit(c, loaders) if {
	some l in loaders
	regex.match(concat("", [`\bnew\s+`, l, `\s*\(`]), c)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "ClassLoader")
	regex.match(`\b(?:javax|jakarta)\.ejb\b`, content)
	regex.match(_ejb_re, content)
	not helpers.is_test_path(path)
	loaders := {m[1] | some m in regex.find_all_string_submatch_n(`class\s+(\w+)\s+extends\s+(?:\w+\.)*\w*ClassLoader\b`, content, -1)}
	lines := split(content, "\n")
	some i, line in lines
	_maybe(line, loaders)
	not helpers.is_comment_line(line)
	_hit(_code(line), loaders)
	finding := {
		"rule_id": metadata.id,
		"message": "Enterprise bean uses a class loader (obtains, creates, replaces or defines classes), which the EJB specification forbids. Let the container load classes, or move this work outside the bean",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_maybe(line, _) if contains(line, "ClassLoader")

_maybe(line, _) if contains(line, "defineClass")

_maybe(line, _) if contains(line, "defineHiddenClass")

_maybe(line, loaders) if {
	some l in loaders
	contains(line, l)
}
