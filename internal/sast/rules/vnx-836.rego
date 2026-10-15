# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_836

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-836",
	"name": "Use of Password Hash Instead of Password for Authentication",
	"description": "Pass-the-hash authentication: a stored password hash (a field or getter named password_hash, passwordHash, hashed_password, pwd_hash, getPasswordHash() and similar) is compared, with ==, !=, ===, .equals(), compare_digest(), MessageDigest.isEqual() or crypto.timingSafeEqual(), directly against a value taken from the request (request.form/args/json/POST/GET/getParameter/getHeader, req.body/query/params/headers, a variable assigned from one a few lines above, a name destructured from req.body, or a Spring @RequestParam/@RequestHeader String parameter) without hashing it on the server. The comparison is judged per clause of the condition (split at &&, ||, and, or), so the hash and the request value must meet in the same comparison; a call left open at the end of the line is read with its next line. Anyone who obtains the hash database can then log in without knowing a single password. Python, Java and JavaScript/TypeScript. Not reported: the request password hashed on the server first (hashlib, pbkdf2, bcrypt, hash_password() and similar on the line or in the assignment), bcrypt.compare/check_password_hash/verify style checks, comparisons of two stored hashes, a hash tested against null/None/undefined/empty, a user looked up by a request value (only the request value itself, or one conversion call around it, taints a variable), and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-836/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [836],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["password-hash-auth", "pass-the-hash", "authentication", "cwe-836"],
}

_exts := {".py", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_field_re := `(?i)password_?hash|hashed_?password|passw(?:or)?d_?hash|pwd_?hash|pw_?hash`

_source_re := `\b(?:request\.(?:form|args|values|json|data|POST|GET|get_json\(\)|getParameter|getHeader|headers|cookies|query_params)|req\.(?:body|query|params|headers|cookies)|ctx\.request\.body|ctx\.query)\b`

_compare_re := `===?|!==?|\.equals(?:IgnoreCase)?\(|compare_digest\(|isEqual\(|timingSafeEqual\(|constant_time_compare\(|secure_compare\(|safeEqual\(`

# Hashing done on the server.
_hash_call_re := `(?i)\b(?:hashlib\.\w+|hmac\.new|create(?:Hash|Hmac)|\w*hash_?pass(?:word|wd)?\w*|make_password|generate_password_hash|bcrypt\w*\.\w+|hashpw|scrypt\w*|pbkdf2\w*|argon2\w*|sha(?:1|224|256|384|512)\w*|md5\w*|digest|hexdigest|DigestUtils\.\w+)\s*\(`

_strip(line) := regex.replace(line, "\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|`[^`]*`", "\"\"")

# The request value is the assigned value itself (optionally wrapped in one
# conversion call such as str() or String()), not an argument to a lookup:
# user = User.query.filter_by(email=request.form["email"]) does not make the
# looked-up user a request value.
_raw_request(line) if {
	regex.match(_source_re, line)
	not regex.match(_hash_call_re, line)
	regex.match(concat("", [`^[^=]*[^=!<>]=\s*(?:await\s+)?(?:[A-Za-z_]\w*\s*\(\s*)?(?:flask\.)?`, _source_re]), line)
}

# Destructuring: const { email, passwordHash } = req.body
_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:req|ctx\.request)\.(?:body|query|params|headers)\b`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	ps := split(trim_space(part), ":")
	n := trim_space(ps[count(ps) - 1])
	regex.match(`^[A-Za-z_]\w*$`, n)
}

_delta(line) := count(regex.find_all_string_submatch_n(`\(`, line, -1)) - count(regex.find_all_string_submatch_n(`\)`, line, -1))

_open_at_end(lines, i, raw) if {
	i + 1 < count(lines)
	_delta(_strip(raw)) > 0
}

# A call left open at the end of the line continues on the next one.
_joined(lines, i, raw) := concat(" ", [raw, lines[i + 1]]) if _open_at_end(lines, i, raw)

_joined(lines, i, raw) := raw if not _open_at_end(lines, i, raw)

# A variable assigned from the request, not hashed in the assignment.
_tainted(lines, i) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	_raw_request(lines[j])
	v := helpers.assigned_first(lines[j])
} | {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	contains(lines[j], "{")
	some v in _destructured(lines[j])
}

# Spring handler parameters bound from the request.
_spring_params(lines, i) := {m[1] |
	some j in numbers.range(max([0, i - 12]), i - 1)
	contains(lines[j], "@Request")
	some m in regex.find_all_string_submatch_n(`@Request(?:Param|Header)\b[^@]*?\b(?:String|char\[\])\s+(\w+)`, lines[j], -1)
}

_from_request(_, _, line) if regex.match(_source_re, line)

_from_request(lines, i, line) if {
	some v in _tainted(lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), _without_stored(line))
}

_from_request(lines, i, line) if {
	contains(line, ".")
	some v in _spring_params(lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), _without_stored(line))
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(_field_re, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(_field_re, raw)
	not helpers.is_comment_line(raw)
	line := _strip(_joined(lines, i, raw))
	not regex.match(_hash_call_re, line)
	some clause in regex.split(`\|\||&&|\band\b|\bor\b`, line)
	regex.match(_field_re, clause)
	regex.match(_compare_re, clause)
	not regex.match(`(?i)(?:===?|!==?|\bis(?:\s+not)?)\s*(?:null|none|undefined|nil|""|'')(?:\W|$)`, clause)
	_from_request(lines, i, clause)
	finding := {
		"rule_id": metadata.id,
		"message": "Stored password hash compared directly with a value from the request: the hash itself has become the password (pass-the-hash). Accept the password and verify it on the server with bcrypt/argon2/PBKDF2",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# The line with the stored-hash expression (receiver included) removed, so a
# user looked up from request.form["email"] does not taint user.password_hash.
_without_stored(line) := regex.replace(line, `(?i)\b[A-Za-z_][\w\.]*?(?:\(\))?\.(?:get_?)?\w*?(?:password_?hash|hashed_?password|passw(?:or)?d_?hash|pwd_?hash|pw_?hash)\w*(?:\(\))?`, "")
