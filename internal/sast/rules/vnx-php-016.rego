package vulnetix.rules.vnx_php_016

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-016",
	"name": "PHP weak hash function (md5/sha1)",
	"description": "A password is hashed with MD5 or SHA-1, fast unsalted digests that GPUs and rainbow tables reverse in bulk. Reported: md5(), sha1(), hash('md5'|'sha1'|'md4'|'md2', ...) and MD5-crypt (crypt() with a '$1$' salt) when an argument names a password (a variable, property or array key such as $pass, $pass_new, $password, $userPassword, $pwd, $_POST['password'], $input['passwd']) or when the result is assigned to one ($user->password = md5(...), $hashedPassword = sha1(...), 'password' => md5(...)). Not reported: password_hash()/password_verify(), md5/sha1 of non-credential data (cache keys, ETags, checksums, md5_file(), the SHA-1 prefix sent to the Have I Been Pwned range API), hash('sha256', ...) (a fast hash for passwords is still weak but outside this rule), lookalike names such as $bypass, and the call inside a comment or a string literal. Any MD5/SHA-1 use regardless of purpose is reported by VNX-327, VNX-CRYPTO-001 and VNX-CRYPTO-002.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-016/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [328],
	"capec": ["CAPEC-55"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["weak-crypto", "hashing", "php"],
}

_lit_re := `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

_code(line) := regex.replace(line, _lit_re, `''`)

_args_re := `((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`

_call_re := `(?i)(?:^|[^\w>:$\\])(?:md5|sha1)\s*\(|\bhash\s*\(|\bcrypt\s*\(`

# The argument lists of every weak-hash call on the line.
_weak_args(line) := {a |
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)(?:^|[^\w>:$\\])(?:md5|sha1)\s*\(`, _args_re]), line, -1)
	a := m[1]
} | {a |
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)\bhash\s*\(\s*['"](?:md5|sha1|md4|md2)['"]\s*,`, _args_re]), line, -1)
	a := m[1]
} | {a |
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)\bcrypt\s*\(`, _args_re]), line, -1)
	regex.match(`,\s*['"]\$1\$`, m[1])
	a := m[1]
}

_pw_name_re := `(?i)^(pass|pw|pwd|passwd|password|passphrase)$|passw(or)?d|passwd|passphrase|pwd|^pass_|_pass$|^(new|old|cur|curr|current|confirm|user|plain|admin|login)_?pass`

_names(text) := {n |
	some m in regex.find_all_string_submatch_n(`\$(\w+)|->(\w+)|\[\s*['"](\w+)['"]\s*\]`, text, -1)
	n := concat("", [m[1], m[2], m[3]])
}

_password(text) if {
	some n in _names(text)
	regex.match(_pw_name_re, n)
}

# The name the result is stored under: $var = , $obj->prop = , $arr['key'] = ,
# or 'key' => in an array literal.
_lhs_name(line) := n if {
	m := regex.find_all_string_submatch_n(`^\s*['"](\w+)['"]\s*=>`, line, 1)
	n := m[0][1]
}

_lhs_name(line) := n if {
	not regex.match(`^\s*['"]\w+['"]\s*=>`, line)
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)((?:->\w+|\[\s*['"]?\w+['"]?\s*\])*)\s*\.?=[^=>]`, line, 1)
	n := _last(m[0][1], m[0][2])
}

_last(base, "") := base

_last(_, chain) := n if {
	chain != ""
	ms := regex.find_all_string_submatch_n(`(\w+)['"]?\s*\]?\s*$`, chain, 1)
	n := ms[0][1]
}

_weak_for_password(line) if {
	some a in _weak_args(line)
	_password(a)
}

_weak_for_password(line) if {
	count(_weak_args(line)) > 0
	regex.match(_pw_name_re, _lhs_name(line))
}


findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`(?i)\b(md5|sha1|hash|crypt)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)(md5|sha1|hash|crypt)\s*\(`, line)
	not helpers.is_comment_line(line)
	regex.match(_call_re, _code(line))
	_weak_for_password(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password hashed with MD5/SHA-1, which is fast and unsalted; use password_hash($password, PASSWORD_ARGON2ID or PASSWORD_BCRYPT) and password_verify()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
