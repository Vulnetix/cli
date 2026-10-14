# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_321

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-321",
	"name": "Hard-coded cryptographic key",
	"description": "A variable or field named as a cryptographic key (secret_key, api_key, private_key, encryption_key, signing_key, hmac_key, aes_key, master_key) is assigned a literal that looks like key material: at least 16 characters with no spaces, not a placeholder or an environment lookup. A variable that merely ends in 'key' (a map key, a cache key, a loop variable named key) is not a cryptographic key, and its value is not a secret.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-321/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [321],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "hardcoded-key", "cwe-321"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

_skip(path) if endswith(path, ".min.css")

_skip(path) if endswith(path, ".min.html")

# The name says it is a cryptographic key, as a whole identifier segment.
_key_name := `(?i)\b(?:\w*[_\.\-])?(?:secret_?key|api_?key|private_?key|encryption_?key|signing_?key|hmac_?key|aes_?key|master_?key|crypto_?key|jwt_?secret|cipher_?key)\b["']?\s*(?::=|=|:)\s*(?:b|r|u)?["'\x60]([^"'\x60]*)["'\x60]`

# Not key material: placeholders, templates, lookups.
_placeholder(v) if regex.match(`(?i)(changeme|change_me|your[_\-]|example|placeholder|xxxx|todo|dummy|sample|<|>|\$\{|\{\{|%[sdv]|process\.env|os\.environ|getenv)`, v)

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	not helpers.is_test_path(path)
	some _ext in {".py", ".java", ".js", ".ts", ".go", ".mjs", ".jsx", ".tsx"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	some hit in regex.find_all_string_submatch_n(_key_name, line, 3)
	value := hit[1]
	count(value) >= 16
	not contains(value, " ")
	not _placeholder(value)
	finding := {
		"rule_id": metadata.id,
		"message": "Hard-coded cryptographic key — rotate into a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
