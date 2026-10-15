# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_912

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-912",
	"name": "Hidden functionality: master password or hidden account in a credential check",
	"description": "A credential check carries a hidden way in (CWE-912): on one condition line, the real verification (check_password, password_verify, bcrypt/argon compare, authenticate, matches, verify, checkpw) is OR-ed with a comparison of the supplied password, passphrase, PIN, token, secret or API key against a hard-coded string literal (password == \"Spring2019!\", \"x\".equals(token)), so a master password logs in as anyone (on an if/elif/elsif/unless/return line, or an assignment whose expression starts with the credential: ok = password === \"x\" || bcrypt.compare(...)); or a username and a password are both compared to literals in one AND-ed condition, a hidden built-in account. Reported in Go, Java, JavaScript/TypeScript, PHP, Python and Ruby. Not reported: comparisons with empty or two-character literals, != tests, password-policy checks that are not OR-ed with a verifier, an OR with a negated verifier (token === \"undefined\" || !verifyToken(token), which rejects), conditions split across lines, field-type or grant-type comparisons (type === 'password'), test files, comments and string literals. A hidden request parameter that grants access is VNX-656; hard-coded credentials in general are VNX-798.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-912/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [912],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["backdoor", "hidden-functionality", "master-password", "cwe-912"],
}

_exts := {".go", ".java", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".php", ".py", ".rb"}

# A credential-named expression (the last segment of a name, a request member
# or a subscript) compared to a literal of at least three characters.
_cred := `(?i)(?:\w*(?:password|passwd|passphrase|secret|token|api_?key|auth_?key)|\b(?:pwd|pass|pw|pin))['"\]]*`

_lit := `["'][^"'\s][^"']{2,}["']`

_cred_eq := concat("", [_cred, `\s*===?\s*`, _lit, `|`, _lit, `\s*===?\s*(?:\$|@)?[\w\.\[\]'":>-]*`, _cred, `|`, _cred, `\s*\.equals\(\s*`, _lit, `\s*\)|`, _lit, `\s*\.equals\(\s*[\w\.]*`, _cred])

_user_eq := `(?i)\w*(?:user(?:_?name)?|login|account)['"\]]*\s*===?\s*["'][^"']{2,}["']`

_verify := `(?i)check_?password|password_verify|checkpw|bcrypt|argon|compare(?:_digest|hash)?\s*\(|authenticate\s*\(|\.matches\s*\(|verify\w*\s*\(|validate_?password`

_or := `\|\||\bor\b`

_and := `&&|\band\b`

_reported(line) if {
	regex.match(_or, line)
	regex.match(_verify, line)
	_positive_verify(line)
}

# A verifier call that is not negated: `pw == "x" || !verify(pw)` is a
# rejection path (a default-value or missing-token check), not a way in.
_verify_occ := `(?i)(!\s*\(?\s*|\bnot\s+\(?\s*)?(?:await\s+)?[\w$.]*?(?:check_?password|password_verify|checkpw|bcrypt|argon|compare(?:_digest|hash)?\s*\(|authenticate\s*\(|\.matches\s*\(|verify\w*\s*\(|validate_?password)`

_positive_verify(line) if {
	some m in regex.find_all_string_submatch_n(_verify_occ, line, -1)
	m[1] == ""
}

_reported(line) if {
	regex.match(_and, line)
	regex.match(_user_eq, line)
}

# Cheap whole-file prefilters (substring tests on the lower-cased file): a
# literal compared with == or .equals(, a credential word, and either a
# verifier or a user/account name.
_lit_cmp_tokens := ["== \"", "== '", "==\"", "=='", "\" ==", "' ==", "\"==", "'==", ".equals("]

_cred_words := ["pass", "secret", "token", "pwd", "pw", "apikey", "api_key", "authkey", "auth_key", "pin ", "pin]", "pin'", "pin\"", "pin)", "pin."]

_second_words := ["check_password", "checkpassword", "password_verify", "checkpw", "bcrypt", "argon", "compare", "authenticate", "matches", "verify", "validate_password", "validatepassword", "user", "login", "account"]

_any(s, words) if {
	some w in words
	contains(s, w)
}

# A condition (if/elif/elsif/unless/else if/return) line that compares with ==
# or .equals(, located without splitting the file into lines.
_cond_line := `(?m)^[ \t]*(?:\}[ \t]*)?(?:if|elif|elsif|unless|else[ \t]+if|return)\b[^\n]*(?:==|\.equals\()[^\n]*`

# An assignment of a boolean expression that starts with the credential
# (ok = pw === "x" || verify(...)); searched only in files that OR something
# with a verifier, since only the OR form applies to it.
_assign_line := `(?m)^[ \t]*(?:(?:const|let|var|val|final|boolean|bool)[ \t]+)?[A-Za-z_$][\w$]*[ \t]*(?::[ \t]*\w+[ \t]*)?:?=[ \t]*(?:await[ \t]+)?\(?[ \t]*[\w$.\[\]]*(?i:pass|pwd|pw|secret|token|pin|key)[^\n]*(?:==[ \t]*["']|\.equals\()[^\n]*`

_verify_words := ["check_password", "checkpassword", "password_verify", "checkpw", "bcrypt", "argon", "authenticate(", "validate_password", "validatepassword", "verify_password", "verifypassword", "comparehash", "compare_digest", "encoder.matches"]

_union_candidates(content, lc) := array.concat(regex.find_n(_cond_line, content, -1), _assignments(content, lc))

_assignments(content, lc) := regex.find_n(_assign_line, content, -1) if {
	_any(lc, ["||", " or "])
	_any(lc, _verify_words)
} else := []

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	_any(content, _lit_cmp_tokens)
	lc := lower(content)
	_any(lc, _cred_words)
	_any(lc, _second_words)
	some line in _union_candidates(content, lc)
	regex.match(_cred_eq, line)
	not helpers.is_comment_line(line)
	_reported(line)
	some i, l in split(content, "\n")
	l == line
	finding := {
		"rule_id": metadata.id,
		"message": "A credential check accepts a hard-coded master password, token or built-in account beside the real verification: a hidden way in that works for anyone who reads the code or the binary. Remove it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
