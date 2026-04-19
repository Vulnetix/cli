# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_20

import rego.v1

metadata := {
	"id": "VNX-20",
	"name": "Improper Input Validation",
	"description": "User-controlled data is used directly without validation or sanitization. Accepting unvalidated input can lead to injection attacks, path traversal, denial of service, and unexpected application behaviour.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-20/",
	"languages": ["go", "java", "node", "php", "python", "ruby", "csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [20],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["input-validation", "injection", "cwe-20"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Patterns that indicate unsanitised user input flowing into sensitive sinks
_dangerous_patterns := {
	# Node.js / Express — direct use of req.body/query/params without validation middleware
	"req.body.",
	"req.query.",
	"req.params.",
	# Python Django / Flask — request data direct use
	"request.GET[",
	"request.POST[",
	"request.args[",
	"request.form[",
	"request.data",
	# PHP superglobals
	"$_GET[",
	"$_POST[",
	"$_REQUEST[",
	"$_COOKIE[",
	"$_SERVER[",
	# Ruby on Rails — params without strong parameters
	"params.permit!",
	# Java — HttpServletRequest without validation
	"getParameter(",
	"getQueryString()",
	"getHeader(",
	# Go — r.FormValue / r.URL.Query without validation
	"r.FormValue(",
	"r.URL.Query()",
	"r.PostFormValue(",
	# C# — Request.Form / QueryString without validation
	"Request.Form[",
	"Request.QueryString[",
	"Request.Params[",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _dangerous_patterns
	contains(line, pattern)
	# Exclude lines that clearly validate/sanitize (rudimentary heuristic)
	not contains(line, "validate")
	not contains(line, "sanitize")
	not contains(line, "escape")
	not contains(line, "filter")
	not contains(line, "// ")
	not contains(line, "# ")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Unvalidated user input via '%s'; validate and sanitize all user-controlled data before use", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
