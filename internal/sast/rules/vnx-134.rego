# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_134

import rego.v1

metadata := {
	"id": "VNX-134",
	"name": "Use of externally-controlled format string",
	"description": "Passing user-controlled input directly as the format string argument to printf-family functions (C), fmt.Printf (Go), or logging functions (Python) allows an attacker to read arbitrary memory, write to arbitrary memory, or crash the process.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-134/",
	"languages": ["c", "cpp", "go", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [134],
	"capec": ["CAPEC-135"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["format-string", "injection", "cwe-134"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_c_patterns := {
	"printf(argv",
	"printf(user",
	"printf(input",
	"fprintf(stderr, argv",
	"fprintf(stdout, argv",
	"fprintf(f, user",
	"sprintf(buf, user",
	"syslog(LOG_",
}

_go_patterns := {
	"fmt.Printf(r.",
	"fmt.Printf(req.",
	"fmt.Fprintf(w, r.",
	"fmt.Fprintf(os.Stderr, user",
	"log.Printf(r.",
	"log.Fatalf(r.",
}

_python_patterns := {
	"logging.debug(user",
	"logging.info(user",
	"logging.warning(user",
	"logging.error(user",
	"logging.critical(user",
	"print(user_input",
}

_is_c_file(path) if endswith(path, ".c")
_is_c_file(path) if endswith(path, ".cpp")
_is_c_file(path) if endswith(path, ".cc")
_is_c_file(path) if endswith(path, ".cxx")
_is_c_file(path) if endswith(path, ".h")
_is_c_file(path) if endswith(path, ".hpp")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_c_file(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _c_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible format string injection: user-controlled value passed as format argument near '%v'; always use a literal format string such as printf(\"%%s\", userInput)", [pattern]),
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
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _go_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible format string injection in Go: user-controlled value passed as format argument near '%v'; use fmt.Printf(\"%%s\", value) with an explicit format string", [pattern]),
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
	some pattern in _python_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible format string injection in Python: user-controlled value passed directly to logging/print near '%v'; use logging.info(\"%%s\", value) with an explicit format placeholder", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
