package vulnetix.rules.vnx_go_037

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-037",
	"name": "Missing security headers in HTTP response",
	"description": "A Go web application serves pages to browsers and nothing in the project sets browser security headers (X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, Referrer-Policy, Permissions-Policy, Cross-Origin-*), directly or through a security-headers middleware (unrolled/secure, gin-contrib/secure, echo middleware.Secure, helmet-style SecureHeaders). A page is a response a browser renders: an html/template Execute/ExecuteTemplate into the response writer, a Content-Type of text/html, gin/echo c.HTML(status, ...), echo c.Render(status, ...) or fiber c.Render(\"name\", ...), an http.FileServer/ServeFile, or markup written with fmt.Fprint(w, \"<...\"). Reported once per file, at the first such line, and only when the project is an application (a non-test file declares func main). Not reported: JSON or status-only responses (no page to frame or sniff), libraries and frameworks that only provide a renderer, test servers and mocks, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-037/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [693],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["headers", "security", "http"],
}

# A security header named anywhere, or middleware that sets them.
_mitigation := `X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Strict-Transport-Security|Content-Security-Policy|Referrer-Policy|Permissions-Policy|Cross-Origin-(?:Opener|Resource|Embedder)-Policy|unrolled/secure|gin-contrib/secure|middleware\.Secure(?:WithConfig)?\(|secure\.New\(|(?i:helmet)|SecureHeaders`

# A header set in middleware in one file protects handlers in every other.
_project_sets_headers if {
	some p, content in input.file_contents
	endswith(p, ".go")
	not helpers.is_test_path(p)
	regex.match(_mitigation, content)
}

# The project runs a server (a library that only renders does not decide
# which headers its users send).
_is_application if {
	some p, content in input.file_contents
	endswith(p, ".go")
	not helpers.is_test_path(p)
	regex.match(`(?m)^func main\(\)`, content)
}

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

_page_hint := `Execute|text/html|HTML\(|Render\(|FileServer\(|ServeFile|Fprint|Write\(`

# A line that sends a browser-rendered page.
_page(line, code) if regex.match(`\.Execute(?:Template)?\(\s*(?:w|rw|wr|resp|res|writer|c\.Writer|ctx\.Writer|c\.Response\(\))\s*,`, code)

_page(line, code) if {
	regex.match(`\.Header\(\)\.(?:Set|Add)\(`, code)
	regex.match(`"Content-Type"\s*,\s*"text/html`, line)
}

_page(line, code) if {
	regex.match(`\b(?:c|ctx)\.(?:HTML|Render)\(`, code)
	regex.match(`\b(?:c|ctx)\.(?:HTML|Render)\(\s*(?:http\.Status\w+|\d{3}\s*,|")`, line)
}

_page(_, code) if regex.match(`\bhttp\.(?:FileServer|ServeFile|ServeFileFS|FileServerFS)\(`, code)

_page(line, code) if {
	regex.match(`\bfmt\.Fprint\w*\(\s*(?:w|rw|c\.Writer)\s*,`, code)
	regex.match(`\bfmt\.Fprint\w*\(\s*(?:w|rw|c\.Writer)\s*,\s*"\s*<`, line)
}

_page(line, code) if {
	regex.match(`\b(?:w|rw)\.Write\(\[\]byte\(`, code)
	regex.match(`\.Write\(\[\]byte\(\s*"\s*<`, line)
}

_page_lines(lines) := {i |
	some i, line in lines
	regex.match(_page_hint, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*func\b`, line)
	_page(line, _code(line))
}

findings contains finding if {
	not _project_sets_headers
	_is_application
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(`\.Execute(?:Template)?\(|text/html|\.(?:HTML|Render)\(|http\.(?:FileServer|ServeFile)|Fprint\w*\(\s*\w+\s*,\s*"\s*<|Write\(\[\]byte\(\s*"\s*<`, content)
	lines := split(content, "\n")
	rl := _page_lines(lines)
	count(rl) > 0
	i := min(rl)
	finding := {
		"rule_id": metadata.id,
		"message": "Pages are served without browser security headers (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, ...); set them here or in middleware",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
