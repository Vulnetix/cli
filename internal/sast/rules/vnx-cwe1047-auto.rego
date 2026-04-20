# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1047

import rego.v1

metadata := {
	"id": "VNX-1047",
	"name": "Modules with Circular Dependencies",
	"description": "Circular import or dependency relationships between modules can cause initialization order problems, where security-critical objects (loggers, validators, auth handlers) may not be fully initialized when first used. This can result in security checks being silently bypassed during startup.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1047/",
	"languages": ["python", "node", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1047],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["circular-dependency", "import", "initialization", "code-quality", "cwe-1047"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Python: deferred/lazy imports inside functions (common circular dep workaround)
_python_deferred_import := {
	"    import ",
	"\timport ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _python_deferred_import
	startswith(line, p)
	contains(line, "import ")
	not contains(line, "#")
	finding := {
		"rule_id": metadata.id,
		"message": "Python deferred import inside a function body may indicate a circular dependency workaround; resolve the circular dependency at the module level to ensure security-critical modules are fully initialized before use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
