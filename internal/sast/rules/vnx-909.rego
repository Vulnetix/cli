# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_909

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-909",
	"name": "Missing Initialization of Resource",
	"description": "A Java private field holding an object (a DataSource, Cipher, Map, lock, array ...) that nothing in its class ever assigns, yet the class dereferences it (dataSource.getConnection(), this.cipher.doFinal(...), cache.get(id), allowed.length, synchronized (lock), for (X x : listeners)), so the first use throws NullPointerException. Reported on the field declaration: private, not final, not primitive, no initializer, no annotation (an injection, mock, binding or framework annotation such as @Autowired, @Inject, @Mock, @Value, @BindView), and no assignment anywhere in the file (name = ..., this.name = ..., other.name = ..., in a constructor, setter, initializer block or lazy if (x == null) x = ...). Not reported: classes whose fields a framework or Lombok fills (@Data, @Setter, @Builder, @AllArgsConstructor, @Value, @Entity, @Embeddable, @Document, @XmlRootElement, JSON-mapped DTOs annotated as such), files using reflection (setAccessible(true)), fields shadowed by a parameter, lambda or loop variable of the same name (unless dereferenced through this.), primitives (which default to 0/false), final fields (the compiler enforces their initialization), test sources, comments and strings. A field assigned by a serializer without annotations (plain Gson) is invisible to the rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-909/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [909],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-initialization-of-resource", "cwe-909", "null-pointer"],
}

# `private [static] [volatile|transient] Type name;` with a reference type.
_field_re := `^\s*private\s+(?:static\s+)?(?:(?:volatile|transient)\s+)*([A-Z][\w.]*(?:<[^;=()]*>)?(?:\s*\[\s*\])*)\s+([a-z_$][\w$]*)\s*;\s*(?://.*)?$`

# A framework or Lombok fills the fields, or reflection may.
_framework_filled := `@(?:Data|Setter|Builder|SuperBuilder|AllArgsConstructor|Value|Jacksonized|Entity|Embeddable|MappedSuperclass|Document|XmlRootElement|XmlAccessorType|JsonAutoDetect|ConfigurationProperties|Parcel|AutoValue)\b|setAccessible\s*\(\s*true`

# The previous code line is an annotation (it applies to this field).
_annotated(lines, i, line) if contains(line, "@")

_annotated(lines, i, _) if {
	i > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`^\s*@\w+`, lines[j])
	not _code_between(lines, j, i)
}

_code_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	t := trim_space(lines[k])
	t != ""
	not startswith(t, "@")
	not startswith(t, "//")
	not startswith(t, "*")
	not startswith(t, "/*")
	not startswith(t, ")")
}

# Code of the file with comments and string literals removed.
_code(content) := regex.replace(regex.replace(content, `(?s)/\*.*?\*/|//[^\n]*`, ""), `"(?:\\.|[^"\\\n])*"`, `""`)

_assigned(code, name) if regex.match(concat("", [`\b`, name, `\s*(?:=[^=]|\+=|-=|\+\+|--)`]), code)

# A parameter, lambda, catch or loop variable of the same name shadows it.
_shadowed(code, name) if regex.match(concat("", [`[(,]\s*(?:final\s+)?[\w.<>\[\]?, ]*[\w>\]]\s+`, name, `\s*[,)]|\b`, name, `\s*->|[(,]\s*`, name, `\s*[,)]\s*->|\b`, name, `\s*:[^:]`]), code)

_dereferenced(code, name) if regex.match(concat("", [`(?:^|[^\w.$]|this\.)`, name, `\s*(?:\.\s*[A-Za-z_]|\[)|synchronized\s*\(\s*(?:this\.)?`, name, `\s*\)|:\s*(?:this\.)?`, name, `\s*\)`]), code)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "private ")
	not helpers.is_test_path(path)
	not regex.match(_framework_filled, content)
	lines := split(content, "\n")
	code := _code(content)
	some i, line in lines
	startswith(trim_left(line, " \t"), "private ")
	m := regex.find_all_string_submatch_n(_field_re, line, 1)
	count(m) > 0
	name := m[0][2]
	not _annotated(lines, i, line)
	not _assigned(code, name)
	_used_as_field(code, name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Field '%s' (%s) is never initialized in this class but is used: it stays null, so the first use throws NullPointerException. Initialize it at its declaration or in the constructor, or inject it explicitly", [name, m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A same-named parameter, lambda or loop variable may be what is dereferenced,
# so a shadowed field counts only when it is dereferenced through `this.`.
_used_as_field(code, name) if {
	not _shadowed(code, name)
	_dereferenced(code, name)
}

_used_as_field(code, name) if {
	_shadowed(code, name)
	regex.match(concat("", [`\bthis\.`, name, `\s*(?:\.\s*[A-Za-z_]|\[)|synchronized\s*\(\s*this\.`, name, `\s*\)|:\s*this\.`, name, `\s*\)`]), code)
}
