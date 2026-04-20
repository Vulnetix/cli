# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1004

import rego.v1

metadata := {
	"id": "VNX-1004",
	"name": "Sensitive Cookie Without 'HttpOnly' Flag",
	"description": "The software uses a cookie to store sensitive information but does not set the HttpOnly flag, allowing scripts to access the cookie value.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1004/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1004],
	"capec": ["CAPEC-31"],
	"attack_technique": ["T1539"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cookie", "httponly", "session", "xss", "cwe-1004"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	content := input.file_contents[path]
	contains(content, "http.Cookie{")
	not contains(content, "HttpOnly: true")
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "http.Cookie{")
	finding := {
		"rule_id": metadata.id,
		"message": "http.Cookie created without HttpOnly: true. Without HttpOnly, JavaScript can read the cookie via document.cookie, enabling session theft via XSS; add HttpOnly: true to the cookie definition.",
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
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "res.cookie(")
	not contains(line, "httpOnly: true")
	not contains(line, "httpOnly:true")
	finding := {
		"rule_id": metadata.id,
		"message": "res.cookie() called without httpOnly: true option. Without httpOnly, client-side scripts can access this cookie; pass { httpOnly: true } in the options object.",
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
	not _is_comment_line(line)
	contains(line, "setcookie(")
	not contains(line, "true,")
	not contains(line, "httponly")
	finding := {
		"rule_id": metadata.id,
		"message": "setcookie() called without the httponly flag. The 7th parameter of setcookie() should be true to prevent JavaScript access; use setcookie(name, value, expires, path, domain, secure, true).",
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
	not _is_comment_line(line)
	contains(line, "set_cookie(")
	not contains(line, "httponly=True")
	not contains(line, "httponly = True")
	finding := {
		"rule_id": metadata.id,
		"message": "Flask set_cookie() called without httponly=True. Without this flag, JavaScript can read the cookie; add httponly=True to the set_cookie() call.",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
