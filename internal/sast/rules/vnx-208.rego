# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_208

import rego.v1

metadata := {
	"id": "VNX-208",
	"name": "Observable Timing Discrepancy (Timing Attack)",
	"description": "Secret values (tokens, passwords, HMACs) are compared using standard equality operators that short-circuit on the first mismatched byte. Timing differences reveal information about the secret to remote attackers who can measure response times.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-208/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [208],
	"capec": ["CAPEC-462"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["timing-attack", "side-channel", "secret-comparison", "cwe-208"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")

# Python: direct equality comparison of secrets
_python_secret_compare := {
	"if secret == ",
	"if token == ",
	"if hmac == ",
	"if signature == ",
	"if api_key == ",
	"if password == ",
	"if digest == ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _python_secret_compare
	contains(line, p)
	not contains(line, "hmac.compare_digest(")
	not contains(line, "secrets.compare_digest(")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Python direct comparison '%s' is vulnerable to timing attacks; replace with hmac.compare_digest(a, b) or secrets.compare_digest(a, b) for constant-time secret comparison", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Go: direct equality comparison of secrets
_go_secret_compare := {
	"if token == stored",
	"if secret == ",
	"if hmac == ",
	"if signature == ",
	"if apiKey == ",
	"if token == expected",
	"if digest == ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _go_secret_compare
	contains(line, p)
	not contains(line, "subtle.ConstantTimeCompare(")
	not contains(line, "hmac.Equal(")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Go direct secret comparison '%s' is vulnerable to timing attacks; use subtle.ConstantTimeCompare([]byte(a), []byte(b)) from crypto/subtle for constant-time comparison", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java: String.equals() for secrets
_java_secret_compare := {
	"token.equals(",
	"secret.equals(",
	"hmac.equals(",
	"signature.equals(",
	"apiKey.equals(",
	"password.equals(",
	"digest.equals(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _java_secret_compare
	contains(line, p)
	not contains(line, "MessageDigest.isEqual(")
	not contains(line, "constantEquals(")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Java '%s' uses String.equals() for secret comparison which is not constant-time; use MessageDigest.isEqual(a.getBytes(), b.getBytes()) for timing-safe comparison", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# PHP: == comparison for tokens
_php_secret_compare := {
	"$token == $stored",
	"$token == $expected",
	"$secret == $",
	"$hmac == $",
	"$signature == $",
	"$api_key == $",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _php_secret_compare
	contains(line, p)
	not contains(line, "hash_equals(")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PHP '%s' uses == for secret comparison which is vulnerable to timing attacks; use hash_equals($known, $user_input) for constant-time string comparison", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Ruby: == comparison for secrets
_ruby_secret_compare := {
	"password == stored",
	"token == expected",
	"secret == ",
	"hmac == ",
	"signature == ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _ruby_secret_compare
	contains(line, p)
	not contains(line, "secure_compare")
	not contains(line, "Digest::HMAC")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Ruby direct secret comparison '%s' is vulnerable to timing attacks; use ActiveSupport::SecurityUtils.secure_compare(a, b) or Rack::Utils.secure_compare(a, b) for constant-time comparison", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# JavaScript: === comparison for secrets
_js_secret_compare := {
	"token === stored",
	"token === expected",
	"secret === ",
	"hmac === ",
	"signature === ",
	"apiKey === ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _js_secret_compare
	contains(line, p)
	not contains(line, "timingSafeEqual(")
	not contains(line, "crypto.timingSafeEqual(")
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("JavaScript direct secret comparison '%s' is vulnerable to timing attacks; use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) for constant-time comparison of secrets", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
