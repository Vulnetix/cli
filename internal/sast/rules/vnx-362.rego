# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_362

import rego.v1

metadata := {
	"id": "VNX-362",
	"name": "Race condition (TOCTOU)",
	"description": "Time-of-check to time-of-use (TOCTOU) race: the state of a resource is verified and then used in a separate, non-atomic operation. An attacker who can manipulate the resource between the check and the use can bypass access controls or cause incorrect behaviour.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-362/",
	"languages": ["c", "cpp", "python", "java", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [362],
	"capec": ["CAPEC-29"],
	"attack_technique": ["T1548"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["race-condition", "toctou", "concurrency", "cwe-362"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_c_patterns := {
	"access(",
	"stat(",
	"lstat(",
}

_python_patterns := {
	"os.access(",
	"os.path.exists(",
	"os.path.isfile(",
	"os.path.isdir(",
}

_java_patterns := {
	".exists()",
	".canRead()",
	".canWrite()",
	".isFile()",
	".isDirectory()",
}

_is_c_file(path) if endswith(path, ".c")
_is_c_file(path) if endswith(path, ".cpp")
_is_c_file(path) if endswith(path, ".cc")
_is_c_file(path) if endswith(path, ".cxx")

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
		"message": sprintf("TOCTOU risk: '%v' check is not atomic with the subsequent use; use O_EXCL with open() or equivalent atomic operations to eliminate the race window", [pattern]),
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
		"message": sprintf("TOCTOU risk in Python: '%v' followed by open/use is a race condition; use try/except around the open() call directly instead of pre-checking existence", [pattern]),
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
	some pattern in _java_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("TOCTOU risk in Java: File.%v check followed by file operation is a race condition; use atomic file operations (Files.createFile with StandardOpenOption.CREATE_NEW) instead", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
