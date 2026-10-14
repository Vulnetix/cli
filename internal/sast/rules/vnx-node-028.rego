package vulnetix.rules.vnx_node_028

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-028",
	"name": "Missing Content-Security-Policy header",
	"description": "Judges the project, not a line: reports the express() application (and an http/https.createServer request handler that answers with text/html) in a project that serves HTML (res.render, res.sendFile, express.static, res.send of markup, a text/html Content-Type) when no code anywhere in the project sets a Content-Security-Policy: no helmet() (which sends a CSP by default), no helmet.contentSecurityPolicy()/csp()/lusca.csp()/expressCspHeader() middleware, no Content-Security-Policy header or meta tag. Also reports helmet configured with contentSecurityPolicy: false. Without a CSP an injected script runs with the page's full authority. Not reported: JSON-only APIs, projects where a CSP is set in any file (middleware, a route, a meta tag), commented-out middleware does not count as a mitigation, test and example files, Koa/Fastify/Next.js servers (their headers are set differently).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-028/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [693],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["csp", "header", "security"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

_skip_path(path) if helpers.is_test_path(path)
_skip_path(path) if regex.match(`(^|/)(examples?|samples?|demos?|node_modules|vendor|dist|build)/`, path)
_skip_path(path) if endswith(path, ".min.js")
_skip_path(path) if endswith(path, ".d.ts")

# Code with block comments and whole-line comments removed.
_code(content) := regex.replace(regex.replace(content, `(?s)/\*.*?\*/|<!--.*?-->`, ""), `(?m)^\s*//.*$`, "")

_csp_mitigation_re := `(?i)content-security-policy|\bhelmet\.contentSecurityPolicy\s*\(|\bcsp\s*\(|lusca\.csp\s*\(|expressCspHeader\s*\(|\bcontentSecurityPolicy\s*\(`

# Cheap substring prefilter before any regex over a whole file.
_mentions_csp(content) if contains(content, "Security-Policy")
_mentions_csp(content) if contains(content, "security-policy")
_mentions_csp(content) if contains(content, "SECURITY-POLICY")
_mentions_csp(content) if contains(content, "ecurityPolicy")
_mentions_csp(content) if contains(content, "csp(")
_mentions_csp(content) if contains(content, "CspHeader(")

_csp_file_exists(_) if {
	some path, content in input.file_contents
	not endswith(path, ".min.js")
	_mentions_csp(content)
	regex.match(_csp_mitigation_re, _code(content))
}

_helmet_file_exists(_) if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "helmet(")
	code := _code(content)
	regex.match(`\bhelmet\s*\(`, code)
	not regex.match(`\bcontentSecurityPolicy\s*:\s*false\b`, code)
}

_csp_set(x) if _csp_file_exists(x)

# helmet() sends a default CSP unless the file disables it.
_csp_set(x) if _helmet_file_exists(x)

_csp_disabled_anywhere(_) if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "contentSecurityPolicy")
	regex.match(`\bcontentSecurityPolicy\s*:\s*false\b`, _code(content))
}

_html_re := `\bres\.(render|sendFile)\s*\(|\bexpress\.static\s*\(|\.send\(\s*['"\x60]\s*<|text/html`

_html_hint(content) if contains(content, "render(")
_html_hint(content) if contains(content, "sendFile(")
_html_hint(content) if contains(content, "static(")
_html_hint(content) if contains(content, "text/html")
_html_hint(content) if contains(content, "send(")

_serves_html(_) if {
	some path, content in input.file_contents
	_is_js(path)
	_html_hint(content)
	not _skip_path(path)
	regex.match(_html_re, content)
}

_app_line(line) if regex.match(`=\s*express\s*\(\s*\)`, line)

_app_line(line) if {
	regex.match(`\bhttps?\.createServer\s*\(\s*(?:\{[^}]*\}\s*,\s*)?(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)`, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	_server_hint(content)
	not _skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`express|createServer`, line)
	not helpers.is_comment_line(line)
	_app_line(line)
	_creates_html_server(content, line)
	_serves_html(path)
	not _csp_set(path)
	not _csp_disabled_anywhere(path)
	finding := {
		"rule_id": metadata.id,
		"message": "This server sends HTML but nothing in the project sets a Content-Security-Policy; add helmet() or a Content-Security-Policy header so an injected script cannot run",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_server_hint(content) if contains(content, "express(")
_server_hint(content) if contains(content, "createServer(")

_creates_html_server(_, line) if regex.match(`express\s*\(`, line)

_creates_html_server(content, line) if {
	contains(line, "createServer")
	contains(content, "text/html")
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "contentSecurityPolicy")
	not _skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "contentSecurityPolicy")
	not helpers.is_comment_line(line)
	regex.match(`\bcontentSecurityPolicy\s*:\s*false\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "helmet is configured with contentSecurityPolicy: false, so no Content-Security-Policy is sent; configure directives instead of disabling it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
