# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_615

import rego.v1


metadata := {
	"id": "VNX-615",
	"name": "Inclusion of Sensitive Information in Source Code Comments",
	"description": "Reports a comment (a whole-line comment: # in Python; //, /* */, a * continuation line or <!-- --> elsewhere; a line inside a /* ... */ block opened by a line starting with /*; or a trailing comment after code, found after string literals are removed) in Go, Java, JavaScript/TypeScript or Python source that records a credential value: a password, passwd, passphrase, secret, client_secret, api_key, access/auth/api/refresh/CSRF/session token, jwt, sessionid, private key or secret/access key name followed by ':' or '=' and a literal of six or more characters containing a digit or a symbol (\"R3port!ng2023\", letmein99, commented-out `String password = \"Adm1n@2024\";`). Comments ship with the source and survive in history, so the credential is disclosed to everyone who can read it. Not reported: parameter documentation (@param password the user's password), prose and type descriptions (password: must be 12 characters, api_key: string), references to the environment, settings or a function call (os.Getenv(...), process.env.X, settings.API_KEY, hash(input)), placeholders (changeme, xxxxxxxx, ********, <your password>, ${VAR}, %(password)s, None), URLs, credentials in code rather than comments (hard-coded credential rules cover those), and provider-format tokens (the secrets rules cover those).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-615/",
	"languages": ["go", "java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [615],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["comments", "information-exposure-comments", "cwe-615"],
}

_exts := {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go"}

_cred := `(?i)\b(?:(?:\w*_)?(?:password|passwd|passphrase|secret|api_?key|(?:auth|access|api|bearer|refresh|csrf|xsrf|session)_?token|jwt|sessionid|private_?key|secret_?key|access_?key)|\w+_pass)\s*[:=]\s*["']?([^\s"'(),;<>{}$%\x60]{6,})["']?(?:\s|[;,)]|\*/|-->|$)`

_placeholder := `(?i)^(?:change_?me|changeit|password|secret|example|sample|dummy|placeholder|redacted|your[-_].*|x{3,}.*|\*+|\.{3,}|none|null|nil|true|false|todo|tbd|undefined|required|optional)$`

# Comment syntax of the file's own language: `--` is not a comment in
# JavaScript and `#` is not one in Go.
_is_comment(path, line) if {
	endswith(path, ".py")
	startswith(trim_space(line), "#")
}

_is_comment(path, line) if {
	not endswith(path, ".py")
	some p in ["//", "/*", "*", "<!--"]
	startswith(trim_space(line), p)
}

_cue := `(?i)(?:pass\w*|secret|api_?key|token|jwt|sessionid|private_?key|access_?key)\s*[:=]`

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

# The comment text of line i: the whole line when it is a comment or lies
# inside a /* ... */ block, else the trailing comment after the code (string
# literals removed first, so "http://..." and "#anchor" are not comments).
_comment_text(path, lines, i) := lines[i] if {
	_is_comment(path, lines[i])
} else := lines[i] if {
	_in_block(path, lines, i)
} else := t if {
	endswith(path, ".py")
	m := regex.find_all_string_submatch_n(`\s#(.*)$`, _strip(lines[i]), 1)
	t := m[0][1]
} else := t if {
	not endswith(path, ".py")
	m := regex.find_all_string_submatch_n(`(?:^|[\s;,{}()])//(.*)$`, _strip(lines[i]), 1)
	t := m[0][1]
}

# Line i is inside a block comment opened by a line that starts with /* in
# the 30 lines above and not closed before line i.
_in_block(path, lines, i) if {
	not endswith(path, ".py")
	some j in numbers.range(max([0, i - 30]), i - 1)
	startswith(trim_space(lines[j]), "/*")
	not contains(lines[j], "*/")
	not _closed_between(lines, j + 1, i - 1)
}

_closed_between(lines, a, b) if {
	some k in numbers.range(a, b)
	contains(lines[k], "*/")
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`(?i)(?:pass\w*|secret|api_?key|token|jwt|sessionid|private_?key|access_?key)\s*[:=]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_cue, line)
	text := _comment_text(path, lines, i)
	m := regex.find_all_string_submatch_n(_cred, text, -1)
	some hit in m
	v := hit[1]
	regex.match(`[0-9!@#^&*+?]`, v)
	not regex.match(_placeholder, v)
	not contains(v, "://")
	not startswith(v, "/")
	not regex.match(`^[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+$`, v)
	finding := {
		"rule_id": metadata.id,
		"message": "Comment records a credential value; anyone with the source or its history can read it. Remove it and rotate the credential",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
