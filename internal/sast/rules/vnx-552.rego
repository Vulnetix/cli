# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_552

import rego.v1

metadata := {
	"id": "VNX-552",
	"name": "Files or directories accessible to external parties",
	"description": "Serving sensitive files (.env, .git, config files, database credentials) via a web server allows attackers to harvest secrets, source code, and configuration data without authentication.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-552/",
	"languages": ["python", "java", "php", "ruby", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [552],
	"capec": ["CAPEC-87"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["information-disclosure", "misconfiguration", "web-server"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"express.static(__dirname",
	"express.static('./'",
	"express.static(\".\"",
	"serveStatic(__dirname",
	"MEDIA_ROOT = BASE_DIR",
	"MEDIA_ROOT = os.path.join(BASE_DIR",
	"STATICFILES_DIRS = [BASE_DIR",
	"DocumentRoot /var/www/html",
	"allow from all",
	"Options +Indexes",
	"autoindex on",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential file exposure: '%v' may serve sensitive directories or enable directory listing — restrict web-accessible paths to public assets only", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
