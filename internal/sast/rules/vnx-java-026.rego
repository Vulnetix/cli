package vulnetix.rules.vnx_java_026

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-026",
	"name": "Java Spring/servlet file serving without access control",
	"description": "A Spring @GetMapping or servlet handler returns a FileSystemResource, InputStreamResource, or raw byte stream from a user-supplied path without verifying that the requesting user is authorised to access that file. This exposes arbitrary files to any authenticated or unauthenticated user.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-026/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [552],
	"capec": ["CAPEC-87"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["access-control", "file-exposure", "spring", "java"],
}

_is_java(path) if endswith(path, ".java")

_java_source_re := `getParameter|PathVariable|RequestParam|RequestBody|getPathInfo`

# A Spring handler binds the path in its signature and constructs the resource
# a few statements later, so the annotation and the resource construction are
# never on the same line. The window is measured from the resource line back
# over the handler body to its signature.
_user_input(lines, i) if regex.match(_java_source_re, lines[i])

_user_input(lines, i) if helpers.has_tainted_var(lines, i, 12, _java_source_re)

# Spring binds `@PathVariable String filename` as a parameter rather than an
# assignment, so also accept a bound handler parameter whose name the resource
# line (or a local it was derived from) references.
_user_input(lines, i) if _bound_param_used(lines, i)

_bound_param_used(lines, i) if {
	start := max([0, i - 12])
	some j in numbers.range(start, i)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(`@(PathVariable|RequestParam|RequestBody|RequestHeader)`, prev)
	some name in regex.find_n(`[A-Za-z_][A-Za-z0-9_]*\s*[,)]`, prev, -1)
	ident := regex.find_n(`[A-Za-z_][A-Za-z0-9_]*`, name, 1)[0]
	helpers.reaches(lines, j, i, ident)
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`new\s+FileSystemResource\s*\(`, line)
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "FileSystemResource constructed from user-supplied path without access control check; verify the requesting user is authorised to access the file before returning it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	contains(line, "new InputStreamResource(")
	_user_input(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "InputStreamResource returned for a user-specified resource without authorisation check; restrict file access to authorised users only",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
