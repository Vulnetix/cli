# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_224

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-224",
	"name": "Obscured Security-relevant Information by Alternate Name",
	"description": "A log call (console.*, logger.*, log.*, logging.*, winston, pino) writes a credential under an alternate encoding: the argument is btoa(), Buffer.from(x).toString('base64'), base64.b64encode()/urlsafe_b64encode()/standard_b64encode()/b32encode()/b16encode()/encodebytes() of a value named as a secret (password, passwd, pwd, secret, api key, access/private key, token, credential, bearer), inline or through a variable assigned from such an encoding in the six lines above; a log call broken over several lines is judged as the whole call. The secret word must end the name, so passwordPolicy, tokenizer and apiKeyId are not credentials. Base64 is a reversible alternate name for the value, not a protection, so the log records the credential itself while reading as if it had been hidden. JavaScript, TypeScript and Python. Not reported: base64 of values not named as secrets (images, file names), an encoded credential that is built but not logged (a Basic auth header), the .length or len() of an encoded value, values hashed before encoding (hashlib, sha256, createHash, digest, bcrypt), the pattern inside a plain string literal or a comment, and test code. Whether a log records an entity under a non-canonical name in the wider CWE-224 sense is not decidable line by line and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-224/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [224],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["obscured-security-info", "cwe-224", "logging", "base64"],
}

_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"}

_log_re := `\b(?:console|logger|log|logging|winston|pino|_logger|LOGGER|LOG|Logger)\.(?:log|info|warn|warning|error|debug|trace|fatal|critical|exception)\s*\(`

# The secret word must end the name (or be followed by a non-letter), so
# passwordPolicy, tokenizer and apiKeyId are not credentials.
_secret_re := `(?i)(?:passw(?:or)?d|passwd|\bpwd|secret|secret_?key|api_?key|access_?key|private_?key|token|credentials?|bearer)(?:$|[^a-z])`

# An argument that is hashed before it is encoded is not the credential.
_hashed_re := `(?i)\b(?:hashlib|sha(?:1|224|256|384|512)|md5|hmac|createHash|digest|hash_password|bcrypt|scrypt|argon2)\b`

_secret_arg(arg) if {
	regex.match(_secret_re, arg)
	not regex.match(_hashed_re, arg)
}

_enc_call_re := `\b(?:btoa|b64encode|urlsafe_b64encode|standard_b64encode|b32encode|b16encode|encodebytes)\s*\(\s*((?:[^()]|\([^()]*\))*)\)`

_buf_call_re := `\bBuffer\.from\(\s*((?:[^()]|\([^()]*\))*)\)\.toString\(BASE64\)`

# The source of a two-line flow: an encoding whose argument names a secret.
_enc_source_re := `(?i)(?:\b(?:btoa|b64encode|urlsafe_b64encode|standard_b64encode|b32encode|b16encode|encodebytes)\s*\(|Buffer\.from\()[^;]*(passw(?:or)?d|passwd|\bpwd|secret|api_?key|access_?key|private_?key|token|credentials?|bearer)(?:$|[^a-z])`

_ext_ok(path) if {
	some e in _exts
	endswith(path, e)
}

# Plain string literals are blanked so a message that quotes the pattern is
# not code; f-strings and template literals stay, they evaluate.
_code(line) := c if {
	n := regex.replace(line, `toString\(\s*['"]base64['"]\s*\)`, "toString(BASE64)")
	a := regex.replace(n, `(^|[^fFrRbB\w"'])"(?:[^"\\]|\\.)*"`, `$1""`)
	c := regex.replace(a, `(^|[^fFrRbB\w"'])'(?:[^'\\]|\\.)*'`, `$1''`)
}

_inline(code) if {
	some m in regex.find_all_string_submatch_n(_enc_call_re, code, -1)
	_secret_arg(m[1])
}

_inline(code) if {
	some m in regex.find_all_string_submatch_n(_buf_call_re, code, -1)
	_secret_arg(m[1])
}

_two_line(lines, i, code) if {
	some j in numbers.range(max([0, i - 6]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_enc_source_re, _code(prev))
	not regex.match(_hashed_re, _code(prev))
	v := helpers.assigned_first(prev)

	# The length of an encoded value is not the value.
	rest := regex.replace(code, concat("", [`\b`, v, `\.length\b|\blen\(\s*`, v, `\s*\)`]), "")
	regex.match(concat("", [`\b`, v, `\b`]), rest)
}

# A log call broken over several lines is judged as the whole call: the
# opening line joined with up to five following lines, cut where the
# parentheses balance.
_stmt(_, _, code) := code if {
	strings.count(code, "(") <= strings.count(code, ")")
}

_stmt(lines, i, code) := joined if {
	strings.count(code, "(") > strings.count(code, ")")
	last := min([count(lines) - 1, i + 5])
	ends := [k |
		some k in numbers.range(i + 1, last)
		t := concat(" ", [_code(lines[n]) | some n in numbers.range(i, k)])
		strings.count(t, "(") <= strings.count(t, ")")
	]
	end := _first_or(ends, last)
	joined := concat(" ", [_code(lines[n]) | some n in numbers.range(i, end)])
}

_first_or(ends, _) := ends[0] if count(ends) > 0

_first_or(ends, d) := d if count(ends) == 0

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	regex.match(`btoa\(|base64|b64encode|b32encode|b16encode|encodebytes`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_log_re, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(_log_re, code)
	_hit(lines, i, _stmt(lines, i, code))
	finding := {
		"rule_id": metadata.id,
		"message": "A credential is logged base64-encoded: the encoding is reversible, so the log holds the secret itself. Log a non-reversible identifier (a key id or a short hash prefix) or nothing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_hit(_, _, code) if _inline(_strip_hashed(_strip_len(code)))

# An encoding passed straight into a hash function is hashed, not logged.
_strip_hashed(code) := regex.replace(code, `(?i)\b(?:hashlib\.\w+|sha(?:1|224|256|384|512)|md5|bcrypt\.\w+|hash_password)\s*\((?:[^()]|\([^()]*\)|\((?:[^()]|\([^()]*\))*\))*\)`, "0")

# The length of an encoded value is not the value: btoa(token).length,
# Buffer.from(token).toString("base64").length and len(b64encode(token)).
_enc_any := `(?:\b(?:btoa|b64encode|urlsafe_b64encode|standard_b64encode|b32encode|b16encode|encodebytes)\s*\((?:[^()]|\([^()]*\))*\)|\bBuffer\.from\((?:[^()]|\([^()]*\))*\)\.toString\(BASE64\))`

_strip_len(code) := c if {
	a := regex.replace(code, concat("", [_enc_any, `(?:\.decode\([^()]*\))?\.length\b`]), "0")
	c := regex.replace(a, concat("", [`\blen\(\s*(?:[\w.]+\.)?`, _enc_any, `(?:\.decode\([^()]*\))?\s*\)`]), "0")
}

_hit(lines, i, code) if _two_line(lines, i, code)
