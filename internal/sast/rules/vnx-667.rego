# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_667

import rego.v1

metadata := {
	"id": "VNX-667",
	"name": "Improper locking",
	"description": "Mutexes and locks must be acquired and released in matched pairs. Forgetting to call Unlock (or not using defer in Go), releasing without acquiring, or locking in a way that can panic before the paired unlock causes deadlocks or unprotected concurrent access.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-667/",
	"languages": ["go", "java", "python", "c"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [667],
	"capec": ["CAPEC-25"],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["concurrency", "locking", "mutex", "deadlock", "cwe-667"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_go_patterns := {
	".Lock()",
	".RLock()",
}

_python_patterns := {
	".acquire(",
	"threading.Lock()",
	"threading.RLock()",
}

_java_patterns := {
	".lock()",
	"synchronized (",
	"ReentrantLock(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _go_patterns
	contains(line, pattern)
	not contains(line, "defer")
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Mutex '%v' acquired without a paired 'defer .Unlock()' on the same line or immediately after; missing defer means the lock may not be released if the function returns early or panics", [pattern]),
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
	not contains(line, "with ")
	not contains(line, "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Lock operation '%v' used without a 'with' context manager; use 'with lock:' to guarantee the lock is released even if an exception is raised", [pattern]),
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
		"message": sprintf("Lock acquisition '%v' detected; ensure every acquisition is paired with an unlock in a finally block to prevent lock leaks on exception paths", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
