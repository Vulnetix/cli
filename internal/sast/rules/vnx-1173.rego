# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1173

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1173",
	"name": "Improper Use of Validation Framework",
	"description": "Reports Java code that has a validation framework available but leaves an input path out of it. Reported: in a Spring @Controller/@RestController that validates request bodies with @Valid elsewhere in the same file, a handler parameter bound with @RequestBody (including @RequestBody(required = false) and with other annotations such as @NotNull beside it) to an application type (a DTO, or a List/Set of one) without @Valid or @Validated (fully qualified @jakarta.validation.Valid counts), so that endpoint accepts the object unchecked; Bean Validation constraints (@Size, @Pattern, @Max, @NotBlank and the rest) on a @RequestParam, @PathVariable or @RequestHeader parameter in a controller with no @Validated anywhere in the file, which Spring before Framework 6.1 silently ignores (skipped when the project pins Spring Boot 3.2+ or Spring Framework 6.1+ in pom.xml (parent, spring-boot.version property or spring-boot-dependencies import), build.gradle(.kts), a Gradle version catalog or gradle.properties, where controller method validation is built in); and a Struts 1 <action> mapping with validate=\"false\", which skips the ActionForm and Validator checks. Not reported: bodies bound to String, Map, JsonNode and other raw types, controllers that never use @Valid (the rule cannot tell which DTOs carry constraints), a @Validated controller, validate=\"true\", XML comments, and test files. A BindingResult that is declared and never read is VNX-20's finding.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1173/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1173],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-use-validation-framework", "cwe-1173"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_controller(content) if regex.match(`@(?:Rest)?Controller\b`, content)

# ── @RequestBody without @Valid, in a controller that uses @Valid ────────

_anns := `((?:@[\w.]+(?:\([^)]*\))?\s+)*)`

_body_re := concat("", [_anns, `@RequestBody(?:\s*\([^)]*\))?\s+`, _anns, `(?:final\s+)?([A-Z][\w.]*)(?:\s*<\s*([A-Z][\w.]*))?`])

_valid_ann := `@(?:[\w.]*\.)?Valid(?:ated)?\b`

_raw_types := {
	"String", "Map", "MultiValueMap", "HashMap", "LinkedHashMap", "Object", "JsonNode", "ObjectNode",
	"ArrayNode", "Resource", "InputStream", "Integer", "Long", "Boolean", "Double", "BigDecimal",
	"HttpEntity", "JSONObject", "JSONArray", "Document",
}

_containers := {"List", "Set", "Collection", "Iterable", "ArrayList"}

_unchecked_type(t, _) if {
	not t in _raw_types
	not t in _containers
}

_unchecked_type(t, arg) if {
	t in _containers
	arg != ""
	not arg in _raw_types
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "@RequestBody")
	regex.match(`@(?:[\w.]*\.)?Valid\b`, content)
	_controller(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@RequestBody")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_body_re, line, -1)
	not regex.match(_valid_ann, m[1])
	not regex.match(_valid_ann, m[2])
	_unchecked_type(m[3], m[4])
	finding := _finding(path, i, line, sprintf("@RequestBody %s is bound without @Valid while this controller validates its other request bodies: constraints on the type are never checked for this endpoint. Add @Valid (or @Validated)", [m[3]]))
}

# ── Parameter constraints in a controller that is not @Validated ────────

_constraint := `@(?:NotNull|NotBlank|NotEmpty|Size|Min|Max|Pattern|Email|Positive|PositiveOrZero|Negative|NegativeOrZero|DecimalMin|DecimalMax|Digits|Length|Range|Past|Future)\b`

_binding := `@(?:RequestParam|PathVariable|RequestHeader)\b`

_param_re := concat("", [
	`(?:`, _binding, `(?:\([^)]*\))?\s+(?:@\w+(?:\([^)]*\))?\s+)*`, _constraint,
	`|`, _constraint, `(?:\([^)]*\))?\s+(?:@\w+(?:\([^)]*\))?\s+)*`, _binding, `)`,
])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`@(?:RequestParam|PathVariable|RequestHeader)\b`, content)
	contains(content, "constraints")
	_controller(content)
	not contains(content, "@Validated")
	not _method_validation_builtin
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_param_re, line)
	not helpers.is_comment_line(line)
	finding := _finding(path, i, line, "Bean Validation constraints on a @RequestParam/@PathVariable/@RequestHeader parameter are only enforced when the controller is annotated @Validated (before Spring Framework 6.1): as written, the constraint is ignored. Annotate the class with @Validated")
}

# Spring Framework 6.1 (Spring Boot 3.2) validates parameter constraints on a
# controller without @Validated. A build that pins such a version is not
# affected.
_boot_modern := `(?:3\.(?:[2-9]|\d\d)|[4-9])\.\d`

_method_validation_builtin if {
	some p, c in input.file_contents
	endswith(p, "pom.xml")
	regex.match(concat("", [`<artifactId>spring-boot-starter-parent</artifactId>\s*<version>`, _boot_modern]), c)
}

_method_validation_builtin if {
	some p, c in input.file_contents
	regex.match(`build\.gradle(?:\.kts)?$`, p)
	regex.match(concat("", [`org\.springframework\.boot['"]?\)?\s+version\s+['"]`, _boot_modern]), c)
}

_method_validation_builtin if {
	some p, c in input.file_contents
	endswith(p, "pom.xml")
	regex.match(`<artifactId>spring-(?:webmvc|context)</artifactId>\s*<version>(?:6\.(?:[1-9]|\d\d)|[7-9])\.`, c)
}

# ── Struts 1 action mapping with validation switched off ────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(lower(path), ".xml")
	contains(lower(path), "struts")
	regex.match(`validate\s*=\s*["']false["']`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`validate\s*=\s*["']false["']`, line)
	not contains(trim_space(line), "<!--")
	_in_action(lines, i)
	finding := _finding(path, i, line, "This Struts action mapping sets validate=\"false\", so its ActionForm's validate() and the Validator rules never run for the request. Remove the attribute or set it to true")
}

_in_action(lines, i) if regex.match(`<action\b`, lines[i])

_in_action(lines, i) if {
	some k in numbers.range(max([0, i - 8]), i - 1)
	regex.match(`<action\b`, lines[k])
	not _tag_closed(lines, k, i)
}

_tag_closed(lines, k, i) if {
	some j in numbers.range(k, i - 1)
	contains(lines[j], ">")
}

# The Boot version held in a Maven property or a BOM import, a Gradle version
# catalog, or gradle.properties.
_method_validation_builtin if {
	some p, c in input.file_contents
	endswith(p, "pom.xml")
	regex.match(concat("", [`<spring-boot\.version>\s*`, _boot_modern]), c)
}

_method_validation_builtin if {
	some p, c in input.file_contents
	endswith(p, "pom.xml")
	regex.match(concat("", [`<artifactId>spring-boot-dependencies</artifactId>\s*<version>`, _boot_modern]), c)
}

_method_validation_builtin if {
	some p, c in input.file_contents
	regex.match(`(?:\.versions\.toml|gradle\.properties)$`, p)
	regex.match(concat("", [`(?mi)^\s*(?:spring[-_.]?boot(?:[-_.]?version)?)\s*[=:]\s*["']?`, _boot_modern]), c)
}
