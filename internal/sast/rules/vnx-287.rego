# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_287

import rego.v1

metadata := {
	"id": "VNX-287",
	"name": "Improper authentication",
	"description": "The code contains patterns indicating disabled, bypassed, or improperly implemented authentication, such as JWT signature verification disabled, algorithm=none, SSL verify=False, or hardcoded authentication decisions.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-287/",
	"languages": ["go", "java", "javascript", "python", "php", "ruby", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [287],
	"capec": ["CAPEC-115", "CAPEC-196"],
	"attack_technique": ["T1078", "T1550"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["auth", "jwt", "bypass", "ssl", "verification"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".md")

_auth_bypass_patterns := {
	# JWT — algorithm none / disabled verification
	`"alg": "none"`,
	`'alg': 'none'`,
	`algorithm: 'none'`,
	`algorithm: "none"`,
	`algorithms=["none"]`,
	`algorithms=['none']`,
	`options={"verify_signature": False}`,
	`options={'verify_signature': False}`,
	`verify=False`,
	`verify_signature: false`,
	# Python requests SSL bypass
	"requests.get(verify=False",
	"requests.post(verify=False",
	"requests.put(verify=False",
	"requests.patch(verify=False",
	"requests.delete(verify=False",
	# PHP loose comparison for auth
	"if ($password ==",
	"if ($pass ==",
	# Ruby — hardcoded auth return
	"return true # auth",
	# Go — InsecureSkipVerify covered by CWE-295 but auth bypass also relevant
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _auth_bypass_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Improper authentication pattern detected (pattern: %s); ensure all authentication checks are enabled and use strong verification", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
