# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1021

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1021",
	"name": "Improper Restriction of Rendered UI Layers (Clickjacking)",
	"description": "Code or configuration that switches off, weakens or removes the browser's frame protection, so any site can load the application in an invisible frame and steer the user's clicks (clickjacking). Reported: Spring Security frameOptions().disable() and headers().disable() in their chained, lambda and method-reference forms (including the chain split over two lines, .frameOptions() or http.headers() then .disable()); an X-Frame-Options header set to ALLOWALL, ALLOW-FROM (ignored by current browsers) or ALLOW in Java, JavaScript/TypeScript, Python, PHP, Ruby, Go, C# and Web.config, with quoted or template-literal values and with the header name and value on consecutive lines of one call; the header removed (removeHeader, header_remove, del, Del, Remove, delete, <remove name=...>) when the same file does not set a restrictive CSP frame-ancestors instead; a CSP frame-ancestors directive whose sources include *, https: or http:; helmet/lusca frameguard: false, xFrameOptions: false or frameguard action allow-from; Django X_FRAME_OPTIONS set to anything other than DENY or SAMEORIGIN and the @xframe_options_exempt decorator; Talisman or Rack::Protection frame_options set to an ALLOW value; Rack::Protection/Sinatra protection with except: :frame_options; secure_headers x_frame_options = OPT_OUT; Rails default_headers emptied; echo SecureConfig XFrameOptions: \"\"; and ASP.NET Core SuppressXFrameOptionsHeader = true. Not reported: DENY and SAMEORIGIN values, frameOptions().sameOrigin()/deny(), frame-ancestors with 'self', 'none' or named hosts, a header removed in a file that sets a restrictive frame-ancestors, the absence of any frame protection (other rules judge missing headers), test and spec code, comments and log strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1021/",
	"languages": ["python", "java", "node", "php", "ruby", "go", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1021],
	"capec": ["CAPEC-103"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["clickjacking", "x-frame-options", "csp", "frame-ancestors", "cwe-1021"],
}

_msg := "Frame protection is disabled or weakened here, so any site can embed this page in an invisible frame and trick users into clicking (clickjacking). Send X-Frame-Options: DENY or SAMEORIGIN, or a CSP frame-ancestors directive listing only the origins that may embed the page"

# ── Languages ────────────────────────────────────────────────────────────

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
}

_lang(path) := "php" if {
	some ext in {".php", ".phtml"}
	endswith(path, ext)
}

_lang(path) := "ruby" if {
	some ext in {".rb", ".rake", ".ru"}
	endswith(path, ext)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "cs" if endswith(path, ".cs")

_lang(path) := "config" if endswith(lower(path), ".config")

# A file can only match when it names a frame setting somewhere
# (frameOptions, X-Frame-Options, XFrameOptions, frame_options, frameguard,
# frame-ancestors, xframe_options_exempt, ...), or, for Spring and Rails,
# disables or empties the whole header set.
_frame_needles := {
	"rameOptions", "rame-Options", "rame-options", "RAME-OPTIONS",
	"RAME_OPTIONS", "rame_options", "rameguard", "ncestors", "NCESTORS", "xframe",
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_line_gate(line) if _has_any(line, _frame_needles)

_line_gate(line) if _has_any(line, {"disable", "default_headers", "allow-from", "ALLOW-FROM"})

_file_gate(content, _) if _has_any(content, _frame_needles)

_file_gate(content, "java") if {
	contains(content, "headers")
	contains(content, "disable")
}

_file_gate(content, "ruby") if contains(content, "default_headers")

# Test and spec code configures permissive headers to assert on them.
_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)(src/test|src/it)/`, path)

# Double- and single-quoted literals blanked, for the Spring call chains,
# where a string never carries the configuration.
_no_strings(line) := regex.replace(line, `"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`, `""`)

# ── Shapes, any language ─────────────────────────────────────────────────

# X-Frame-Options given a value that does not restrict framing.
_allow_value := "(?i)[\"'`]x-frame-options[\"'`]\\s*(?:,|=>|:|\\]\\s*=)\\s*[\"'`]\\s*(?:allowall|allow-from|allow\\b|\\*)"

_php_allow := `(?i)\bheader\s*\(\s*["']\s*x-frame-options\s*:\s*(?:allowall|allow-from|allow\b|\*)`

_xml_allow := `(?i)<add\s+name\s*=\s*["']x-frame-options["']\s+value\s*=\s*["']\s*(?:allowall|allow-from|allow\b)`

_bad(line, lang, _) if {
	lang != "config"
	regex.match(_allow_value, line)
}

_bad(line, "php", _) if regex.match(_php_allow, line)

_bad(line, "config", _) if regex.match(_xml_allow, line)

# The header removed. Fine when the same file sends a restrictive
# frame-ancestors, which is the modern replacement.
_remove_re := `(?i)(?:\b(?:remove|removeheader|header_remove|del|delete|pop|unset|except|without)\s*\(?\s*|\bdel\s+[\w.\[\]'"]*\[\s*)["']x-frame-options["']`

_bad(line, lang, lines) if {
	lang != "config"
	regex.match(_remove_re, line)
	not _restrictive_fa(lines)
}

_bad(line, "config", lines) if {
	regex.match(`(?i)<remove\s+name\s*=\s*["']x-frame-options["']`, line)
	not _restrictive_fa(lines)
}

# A frame-ancestors source list (up to the end of the directive) that admits
# every origin.
_fa_lists(line) := [m[1] | some m in regex.find_all_string_submatch_n(`(?i)frame[-_]?ancestors([^;\]\)\}]*)`, line, -1)]

_wild_source := "(^|[\\s'\"`\\[\\(,{])(\\*|https?:|:https?)($|[\\s'\"`\\]\\),;}])"

_bad(line, _, _) if {
	some l in _fa_lists(line)
	regex.match(_wild_source, l)
}

_restrictive_fa(lines) if {
	some l in lines
	contains(lower(l), "ancestors")
	not helpers.is_comment_line(l)
	some s in _fa_lists(l)
	regex.match(`['"\w:]`, s)
	not regex.match(_wild_source, s)
}

# ── Java: Spring Security ────────────────────────────────────────────────

_spring_re := concat("|", [
	`\.frameOptions\s*\(\s*\)\s*\.disable\s*\(`,
	`\bframeOptions\s*\(\s*\w+\s*->\s*\w+\s*\.disable\s*\(\s*\)\s*\)`,
	`\bframeOptions\s*\(\s*[\w.]*::disable\s*\)`,
	`\.headers\s*\(\s*\)\s*\.disable\s*\(`,
	`\.headers\s*\(\s*\w+\s*->\s*\w+\s*\.disable\s*\(\s*\)\s*\)`,
	`\.headers\s*\(\s*[\w.]*::disable\s*\)`,
])

_bad(line, "java", _) if regex.match(_spring_re, _no_strings(line))

# ── JavaScript: helmet / lusca ───────────────────────────────────────────

_bad(line, "js", _) if regex.match(`\b(?:frameguard|xFrameOptions|xframe)\s*:\s*false\b`, line)

_bad(line, "js", lines) if {
	regex.match(`(?i)\baction\s*:\s*["']allow-from`, line)
	some l in lines
	contains(l, "frameguard")
}

# ── Python: Django / Talisman ────────────────────────────────────────────

_bad(line, "py", _) if {
	m := regex.find_all_string_submatch_n(`^\s*X_FRAME_OPTIONS\s*=\s*["']([^"']*)["']`, line, 1)
	count(m) > 0
	not upper(trim_space(m[0][1])) in {"DENY", "SAMEORIGIN"}
}

_bad(line, "py", _) if regex.match(`^\s*@xframe_options_exempt\b`, line)

# Talisman(frame_options=ALLOW_FROM), Rack::Protection frame_options: 'ALLOW-FROM x'
_bad(line, lang, _) if {
	lang in {"py", "ruby"}
	regex.match(`(?i)\bframe_options\s*(?:=|:|=>)\s*[\w.]*?["':]?allow`, line)
}

# ── Ruby: Rails / Rack::Protection / secure_headers ──────────────────────

_bad(line, "ruby", _) if regex.match(`\bexcept\s*(?::|=>)\s*\[?[^\]\n]*:frame_options\b`, line)

_bad(line, "ruby", _) if regex.match(`(?i)\bx_frame_options\s*=\s*(?:SecureHeaders::OPT_OUT|["']\s*allow)`, line)

_bad(line, "ruby", _) if regex.match(`\bdefault_headers\s*(?:=\s*\{\s*\}|\.clear\b)`, line)

# ── Go: echo / unrolled secure ───────────────────────────────────────────

_bad(line, "go", _) if regex.match(`\bXFrameOptions\s*:\s*""`, line)

_bad(line, "go", _) if regex.match(`(?i)\bCustomFrameOptionsValue\s*:\s*"\s*allow`, line)

# ── C#: ASP.NET Core antiforgery ─────────────────────────────────────────

_bad(line, "cs", _) if regex.match(`\bSuppressXFrameOptionsHeader\s*=\s*true\b`, line)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_file_gate(content, lang)
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(line)
	not helpers.is_comment_line(line)
	_bad(line, lang, lines)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Spring's two-line chain: `.frameOptions()` or `.headers()` alone on a line,
# `.disable()` on the next code line.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "disable")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(?:[\w.]+)?\.(frameOptions|headers)\s*\(\s*\)\s*$`, line)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*\.disable\s*\(`, lines[j])
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A header call broken over lines: the header name alone on one line and the
# permissive value on the next code line.
_split_name := "(?i)^\\s*[\"'`]x-frame-options[\"'`]\\s*,\\s*$"

_split_value := "(?i)^\\s*[\"'`]\\s*(?:allowall|allow-from|allow\\b|\\*)"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	lang != "config"
	regex.match(concat("", ["(?m)", _split_name]), content)
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_split_name, line)
	j := helpers.next_code_index(lines, i, 2)
	regex.match(_split_value, lines[j])
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
