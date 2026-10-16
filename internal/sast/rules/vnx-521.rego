# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_521

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-521",
	"name": "Weak Password Requirements",
	"description": "A password policy written in code accepts passwords shorter than 8 characters (the minimum NIST SP 800-63B and OWASP ASVS require), so short, guessable passwords are allowed. Reported when the minimum is between 2 and 7: a length check on a password-named value (Python len(password) < N / <= N / >= N, JavaScript/TypeScript password.length, Java password.length() or getPassword().length(), C# password.Length); a minimum declared on a password field (Joi/zod/yup .min(N), express-validator isLength({ min: N }), jQuery Validate or Mongoose minlength under a password key, Java @Size/@Length(min = N) on a password field, C# [StringLength(..., MinimumLength = N)] or [MinLength(N)] on a password property, ASP.NET Identity options.Password.RequiredLength = N, Django MinimumLengthValidator OPTIONS min_length); and a Django AUTH_PASSWORD_VALIDATORS = [] that turns every check off. Not reported: minimums of 8 or more, a minimum of 0 or 1 (a presence check, as on a login form), maximum-length checks (password.length > 30), minimums on other fields, the numbers inside messages, comments and strings, minified files and test code. Policies configured outside code (an identity provider, a database setting) are not seen.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-521/",
	"languages": ["java", "node", "python", "csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [521],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["password-policy", "cwe-521"],
}

_exts := {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".cs"}

_in_scope(path) if {
	some ext in _exts
	endswith(path, ext)
	not endswith(path, ".min.js")
}

# A password-named identifier or key (password, newPassword, user[password],
# pwd, passphrase). PasswordStrength... style names still contain the word but
# are excluded where it matters by the shapes below.
_pw := `(?i)pass(?:word|wd|phrase)|\bpwd\b`

# String literals are blanked so a message ("at least 6 characters") or a
# quoted example is not a policy.
_code(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

# ── Length comparisons ───────────────────────────────────────────────────

_cmp_res := [
	`(?i)(?:pass(?:word|wd|phrase)|\bpwd)\w*\s*(?:\(\s*\))?\s*\.\s*length\s*(?:\(\s*\))?\s*(<=|<|>=)\s*(\d+)\b`,
	`(?i)\blen\(\s*[\w.]*(?:\[\s*['"]?\w*['"]?\s*\])*(?:pass(?:word|wd|phrase)|\bpwd)[\w.]*(?:\[\s*['"]?\w*['"]?\s*\])*\s*\)\s*(<=|<|>=)\s*(\d+)\b`,
	`(?i)\blen\(\s*\w+\[\s*['"]\w*(?:pass(?:word|wd|phrase)|pwd)\w*['"]\s*\]\s*\)\s*(<=|<|>=)\s*(\d+)\b`,
]

_min_of("<", n) := n

_min_of(">=", n) := n

_min_of("<=", n) := n + 1

_weak(n) if {
	n >= 2
	n <= 7
}

_cmp_weak(line) if {
	some re in _cmp_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	_weak(_min_of(m[1], to_number(m[2])))
}

# ── Declared minimums ────────────────────────────────────────────────────

_decl_res := [
	`(?i)\b(?:min_?length|minimum_?length)\s*['"]?\s*[:=]\s*(\d+)\b`,
	`\.min\(\s*(\d+)\s*[,)]`,
	`\bisLength\(\s*\{[^}]*\bmin\s*:\s*(\d+)`,
	`\bRequiredLength\s*=\s*(\d+)\b`,
	`@(?:Size|Length)\([^)]*\bmin\s*=\s*(\d+)`,
	`\b(?:Validators\.)?(?i:minLength)\(\s*(\d+)\s*\)`,
	`\bMinLengthValidator\(\s*(?:limit_value\s*=\s*)?(\d+)\s*[,)]`,
	`(?i)\bminRequiredPasswordLength\s*=\s*"?(\d+)`,
]

_decl_min(line) := n if {
	some re in _decl_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	n := to_number(m[1])
	_weak(n)
}

# The minimum belongs to a password: the line names it (password: Joi..., or
# options.Password.RequiredLength) ...
_pw_context(lines, i, raw) if regex.match(_pw, regex.replace(raw, `"[^"]*\s[^"]*"|'[^']*\s[^']*'`, `""`))

# ... the nearest key opened above it is a password key ("user[password]": {) ...
_pw_context(lines, i, raw) if {
	not regex.match(`^\s*(?:@(?:Size|Length)|\[\s*(?:StringLength|MinLength))\(`, raw)
	opens := [j |
		some j in numbers.range(max([0, i - 3]), i - 1)
		regex.match(`[{\[(]\s*$`, lines[j])
		not helpers.is_comment_line(lines[j])
	]
	count(opens) > 0
	regex.match(_pw, lines[opens[count(opens) - 1]])
}

# ... the annotation sits on a password field declared below it ...
_pw_context(lines, i, raw) if {
	regex.match(`^\s*(?:@(?:Size|Length)|\[\s*(?:StringLength|MinLength))\(`, raw)
	fields := [j |
		some j in numbers.range(i + 1, min([count(lines) - 1, i + 5]))
		not regex.match(`^\s*(?:@|\[)`, lines[j])
		trim_space(lines[j]) != ""
	]
	count(fields) > 0
	regex.match(_pw, lines[fields[0]])
}

# ... it continues a builder chain (password: Joi.string()\n  .min(6)) whose
# head names a password ...
_pw_context(lines, i, raw) if {
	regex.match(`^\s*\.`, raw)
	heads := [j |
		some j in numbers.range(max([0, i - 5]), i - 1)
		not regex.match(`^\s*\.`, lines[j])
	]
	count(heads) > 0
	h := heads[count(heads) - 1]
	regex.match(`(?i)(?:pass(?:word|wd|phrase)|\bpwd)\w*["']?\s*[:=(]`, lines[h])
}

# ... or it is the OPTIONS of Django's MinimumLengthValidator.
_pw_context(lines, i, _) if {
	some j in numbers.range(max([0, i - 4]), i)
	contains(lines[j], "MinimumLengthValidator")
}

_message := "Password policy allows passwords shorter than 8 characters. Require a minimum length of at least 8 (NIST SP 800-63B, OWASP ASVS 2.1.1) and check candidates against a breached-password list"

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 400
	regex.match(`(?i)length|len\(|\.min\(|@size\(|minLength\(`, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	_hit(lines, i, line, c)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_hit(_, _, line, c) if _cmp_weak(_code_keep_keys(line))

_hit(lines, i, line, c) if {
	_decl_min(_code_keep_keys(line))
	_pw_context(lines, i, line)
}

# Comparisons may index by a quoted key (len(data["password"]) < 6), so they
# are matched against the line with only whitespace-containing strings blanked.
_code_keep_keys(line) := regex.replace(line, `"[^"]*\s[^"]*"|'[^']*\s[^']*'`, `""`)

# Django with every validator removed.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "AUTH_PASSWORD_VALIDATORS")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^AUTH_PASSWORD_VALIDATORS\s*=\s*(\[\s*\]|\(\s*\))\s*(#.*)?$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "AUTH_PASSWORD_VALIDATORS is empty, so Django accepts any password, including one character long. Configure at least MinimumLengthValidator (min_length >= 8) and CommonPasswordValidator",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
