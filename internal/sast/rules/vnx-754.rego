# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_754

import rego.v1

metadata := {
	"id": "VNX-754",
	"name": "Improper check for unusual or exceptional conditions",
	"description": "Ignoring error return values from system calls, memory allocation, or I/O operations means the program continues executing in an undefined state. In Go, the blank identifier _ is often used to discard errors; in C, malloc and open return values are commonly unchecked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-754/",
	"languages": ["go", "c", "cpp", "java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [754],
	"capec": ["CAPEC-17"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["error-handling", "unchecked-return", "cwe-754"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_go_ignored_error_patterns := {
	"_, err :=",
	"_, _ =",
	"_, _ :=",
}

_c_unchecked_patterns := {
	"= malloc(",
	"= calloc(",
	"= realloc(",
	"= fopen(",
	"= open(",
	"= socket(",
}

_java_empty_catch_patterns := {
	"catch (Exception",
	"catch(Exception",
	"catch (Throwable",
	"catch(Throwable",
}

_python_bare_except := {
	"except:",
	"except Exception:",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _go_ignored_error_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Error value discarded with blank identifier near '%v'; always check the returned error before continuing execution", [pattern]),
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
	endswith(path, ".c")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _c_unchecked_patterns
	contains(line, pattern)
	not contains(line, "if (")
	not contains(line, "if(")
	not contains(line, "assert(")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Return value of '%v' may be unchecked; a NULL or error return indicates failure and using the result without checking causes undefined behaviour", [pattern]),
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
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _java_empty_catch_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Broad exception catch '%v' detected; ensure the catch block handles the exception meaningfully and does not silently swallow errors that indicate real failures", [pattern]),
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
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _python_bare_except
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Bare or overly broad except clause '%v'; catch specific exception types and handle or re-raise them rather than silently swallowing all exceptions", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
