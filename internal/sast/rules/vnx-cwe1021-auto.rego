# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1021

import rego.v1

metadata := {
	"id": "VNX-1021",
	"name": "Improper Restriction of Rendered UI Layers (Clickjacking)",
	"description": "The application does not restrict which sites can embed its pages in frames or iframes. An attacker can load the application in a transparent overlay and trick users into clicking buttons or links that perform unintended actions (clickjacking). Mitigation requires setting X-Frame-Options or frame-ancestors in the Content-Security-Policy header.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1021/",
	"languages": ["python", "java", "node", "php", "ruby", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1021],
	"capec": ["CAPEC-103"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["clickjacking", "x-frame-options", "csp", "frame-ancestors", "cwe-1021"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Express.js: helmet used but frameguard disabled
_express_frameguard_disabled := {
	"frameguard: false",
	"frameguard:false",
	"frameguard({ action: false",
}

# Django: missing xframe_options_deny decorator or X-Frame-Options middleware
_django_missing_frame := {
	"X_FRAME_OPTIONS = 'ALLOWALL'",
	"X_FRAME_OPTIONS = \"ALLOWALL\"",
	"X_FRAME_OPTIONS = 'ALLOW'",
	"X_FRAME_OPTIONS = \"ALLOW\"",
	"@xframe_options_exempt",
}

# PHP: explicit header disabling
_php_frame_allow := {
	"header('X-Frame-Options: ALLOWALL'",
	"header(\"X-Frame-Options: ALLOWALL\"",
	"header('X-Frame-Options: ALLOW'",
	"header(\"X-Frame-Options: ALLOW\"",
}

# Java Spring Security: frameOptions disabled
_java_frame_disabled := {
	"frameOptions().disable()",
	"frameOptions().sameOrigin()",
	".headers().frameOptions().disable()",
	"httpSecurity.headers().frameOptions().disable()",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _express_frameguard_disabled
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Express frameguard protection disabled with '%s'; remove this override to keep clickjacking protection enabled", [p]),
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
	some p in _django_missing_frame
	contains(line, p)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Django frame protection pattern '%s' weakens clickjacking defense; use X_FRAME_OPTIONS = 'DENY' and ensure XFrameOptionsMiddleware is in MIDDLEWARE", [p]),
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
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _php_frame_allow
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP header '%s' allows framing from any origin; use 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent clickjacking", [p]),
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
	some p in _java_frame_disabled
	contains(line, p)
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java Spring Security frame protection disabled with '%s'; enable frame options protection with .frameOptions().deny() to prevent clickjacking", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
