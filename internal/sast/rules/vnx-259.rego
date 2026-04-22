# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_259

import rego.v1

metadata := {
	"id": "VNX-259",
	"name": "CWE-259",
	"description": "Detects source patterns associated with CWE-259 (CWE-259). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-259/",
	"languages": ["csharp", "go", "java", "node", "php", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [259],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["hardcoded-credentials", "cwe-259"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".min.html")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
_is_comment_line(line) if startswith(trim_space(line), "--")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _pat in {"password = \"", "password=\"", "Password =", "passwd = \""}
	contains(line, _pat)
	not contains(line, "os.environ")
	not contains(line, "getenv")
	not contains(line, "process.env")
	finding := {
		"rule_id": metadata.id,
		"message": "Hard-coded password found — move to a secret store / environment variable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
