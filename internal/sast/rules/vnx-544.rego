# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_544

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-544",
	"name": "Missing Standardized Error Handling Mechanism",
	"description": "An Express application is created (const app = express(), or require('express')()) and served or exported (app.listen, module.exports = app, export default app), but no JavaScript or TypeScript file of the project registers an error-handling middleware: no four-argument (err, req, res, next) function (typed or not, its parameters on one line or several; the second parameter must be the request, so browser handlers such as window.onerror do not count), no function or variable named errorHandler/handleErrors-style passed to app.use, and no errorhandler() package. Every failure then falls through to Express's built-in handler, which answers with the stack trace whenever NODE_ENV is not 'production', and each route improvises its own error responses. Reported once, at the express() call. Not reported: an error middleware anywhere in the project (another file counts), express.Router() modules, test and example code, comments and string literals. Python's broad except: pass is reported by VNX-391, not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-544/",
	"languages": ["node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [544],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-standardized-error", "express", "error-handling", "cwe-544"],
}

_is_js(path) if {
	some ext in {".js", ".ts", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
	not endswith(path, ".d.ts")
}

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)(examples?|samples?|demos?|node_modules|vendor|dist|build)/`, path)

# `const app = express()` / `var app: Express = express()`.
_create_re := `^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w.]+\s*)?=\s*(?:express|require\s*\(\s*['"]express['"]\s*\))\s*\(\s*\)`

# A four-parameter error middleware, typed or not, arrow or function.
# The parameter list may be broken over several lines (Prettier does this
# for typed parameters), so it is matched against the whole file; the second
# parameter must be the request, which keeps browser handlers such as
# window.onerror = function (e, source, lineno, colno) out.
_param_handler_re := `\(\s*(err|error|e|ex|exception)\b[^,()]*,\s*_?(req|request)\w*[^,()]*,\s*\w+[^,()]*,\s*\w+[^,()]*,?\s*\)\s*(=>|\{|:)`

_handler_re := `\buse\s*\(\s*[\w.]*(error|Error)\w*\s*[,)(]|\berrorhandler\s*\(|\bErrorRequestHandler\b`

_has_handler if {
	some path, content in input.file_contents
	_is_js(path)
	not _skip(path)
	regex.match(`(?i)err`, content)
	regex.match(_param_handler_re, content)
}

_has_handler if {
	some path, content in input.file_contents
	_is_js(path)
	not _skip(path)
	regex.match(`(?i)err`, content)
	some line in split(content, "\n")
	regex.match(`(?i)err`, line)
	not helpers.is_comment_line(line)
	regex.match(_handler_re, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`express(?:['"]\s*\))?\s*\(\s*\)`, content)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "express")
	m := regex.find_all_string_submatch_n(_create_re, line, 1)
	count(m) > 0
	app := m[0][1]
	_served(content, app)
	not _has_handler
	finding := {
		"rule_id": metadata.id,
		"message": "This Express application has no error-handling middleware anywhere in the project, so every thrown or forwarded error reaches Express's default handler, which sends the stack trace to the client unless NODE_ENV is 'production'. Register one app.use((err, req, res, next) => ...) after the routes that logs the error and returns a generic response",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_served(content, app) if regex.match(concat("", [`(?m)^[^/'"\x60]*\b`, app, `\s*\.listen\s*\(`]), content)

_served(content, app) if regex.match(concat("", [`(?m)^\s*(module\.exports\s*=|export\s+default)\s*`, app, `\b`]), content)

_served(content, app) if regex.match(concat("", [`(?m)\b(createServer|https?\.createServer)\s*\([^)]*\b`, app, `\b`]), content)
