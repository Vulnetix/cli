# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_352

import rego.v1

metadata := {
	"id": "VNX-352",
	"name": "Cross-site request forgery (CSRF)",
	"description": "CSRF protection is disabled or absent. Routes or forms that perform state-changing operations lack CSRF tokens or the framework's built-in protection is explicitly bypassed, allowing attacker-controlled pages to trigger actions on behalf of authenticated users.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-352/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [352],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["csrf", "web", "form", "token", "django", "rails", "express"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_csrf_bypass_patterns := {
	# Django
	"@csrf_exempt",
	"csrf_exempt(",
	"CsrfViewMiddleware",
	# Rails
	"skip_before_action :verify_authenticity_token",
	"skip_before_filter :verify_authenticity_token",
	"protect_from_forgery with: :null_session",
	# Express / Node.js
	"app.disable('x-powered-by')",
	# Generic CSRF disable patterns
	"csrf: false",
	"csrfProtection: false",
	"csrf_protection = False",
	"CSRF_ENABLED = False",
	"csrf_enabled = False",
	"X-CSRF-Token",
	# PHP — missing CSRF field is detected by the absence pattern approach;
	# flag explicit disabling
	"csrf_token() === false",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _csrf_bypass_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CSRF protection appears disabled or bypassed (pattern: %s); ensure all state-changing endpoints are protected with CSRF tokens", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
