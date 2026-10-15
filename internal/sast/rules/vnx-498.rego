# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_498

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-498",
	"name": "Cloneable Class Containing Sensitive Information",
	"description": "A Java class that implements Cloneable (the implements clause may span lines) and declares a non-static field holding a secret: a String, char[], byte[] or CharSequence whose name says password, passwd, passphrase, pwd, pin, secret, API key, private key, an access/refresh/auth/session/bearer/id/csrf token, credential, credit card/card number, CVV or SSN, or a field of type PrivateKey, SecretKey, SecretKeySpec, KeyPair, KeyStore or Key. clone() copies the object without running a constructor, so any caller that can clone it gets a second copy of the secret that no wipe or access check covers. Reported on the class declaration. Not reported: a class whose clone() throws CloneNotSupportedException, static constants (PASSWORD_KEY), names that describe a secret rather than hold it (passwordLength, secretName), classes that are not Cloneable, test code, comments and string literals. Classes that inherit Cloneable from a superclass are not resolved.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-498/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [498],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["cloneable-sensitive", "cwe-498"],
}

_field_re := `^(\s*)(?:@\w+(?:\([^)]*\))?\s+)*((?:(?:private|protected|public|final|transient|volatile|static)\s+)*)(String|char\s*\[\s*\]|byte\s*\[\s*\]|CharSequence|SecretKey|SecretKeySpec|PrivateKey|Key|KeyPair|KeyStore)\s+(\w+(?:\s*,\s*\w+)*)\s*(?:=[^=]|;)`

_key_types := {"SecretKey", "SecretKeySpec", "PrivateKey", "Key", "KeyPair", "KeyStore"}

_secret_name_re := `(?i)password|passwd|passphrase|secret|api_?key|private_?key|(?:access|refresh|auth|session|bearer|id|csrf)_?token|credential|credit_?card|card_?number|^cvv$|^ssn$|^pin$|^pin_?code$|^pwd$`

_describes_re := `(?i)(?:policy|length|len|min|max|required|enabled|field|label|prompt|name|id|url|uri|endpoint|path|file|type|expiry|expires|expiration|count|attempts|regex|pattern|format|hint|header|param|ref|arn|version|validator|strength|rule)s?$`

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_sensitive(typ, _) if typ in _key_types

_sensitive(typ, name) if {
	not typ in _key_types
	regex.match(_secret_name_re, name)
	not regex.match(_describes_re, name)
}

# A class declaration line; group 1 is its indentation.
_class_re := `^(\s*)(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|abstract|final|static|sealed|non-sealed|strictfp)\s+)*class\s+\w+`

_width(s) := count(replace(s, "\t", "    "))

_lead(l) := regex.find_n(`^\s*`, l, 1)[0]

_first(a, _) := a[0] if count(a) > 0

_first(a, d) := d if count(a) == 0

# The class body: from the line after the declaration to the closing brace
# written at the declaration's own indentation (bounded at 800 lines).
_body_end(lines, i, ind) := _first(ends, lim) if {
	lim := min([count(lines), i + 800])
	ends := [k |
		some k in numbers.range(i + 1, lim - 1)
		startswith(lines[k], concat("", [ind, "}"]))
	]
}

# The member depth: the shallowest code line inside the body, so the fields
# of a nested class and the locals of a method are not this class's fields.
_member_width(lines, s, e, cw) := min(ws) if {
	ws := [w |
		some k in numbers.range(s, e - 1)
		l := lines[k]
		trim_space(l) != ""
		w := _width(_lead(l))
		w > cw
	]
	count(ws) > 0
}

# Secret fields declared at member depth of the class on line i, as
# [line index, field name].
_secret_fields(lines, i, ind, excl) := {[k, name] |
	e := _body_end(lines, i, ind)
	s := i + 1
	e > s
	mw := _member_width(lines, s, e, _width(ind))
	some k in numbers.range(s, e - 1)
	line := lines[k]
	regex.match(`String|char|byte|CharSequence|Key`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_field_re, _code(line), 1)[0]
	_width(m[1]) == mw
	not regex.match(excl, m[2])
	some raw in split(m[4], ",")
	name := trim_space(raw)
	_sensitive(regex.replace(m[3], `\s+`, ""), name)
}

_body_text(lines, i, ind) := concat("\n", array.slice(lines, i, _body_end(lines, i, ind) + 1))

# The declaration header: the class line and up to two continuation lines
# before its opening brace.
_header(lines, i) := concat(" ", array.slice(lines, i, min([count(lines), i + 3])))

_refuses_clone(text) if regex.match(`\bclone\s*\(\s*\)[^{;]*\{\s*throw\s+new\s+CloneNotSupportedException`, text)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "Cloneable")
	not helpers.is_test_path(path)
	regex.match(`\bclass\s+\w+[^{;]*\bimplements\s[^{;]*\bCloneable\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "class")
	not helpers.is_comment_line(line)
	cm := regex.find_all_string_submatch_n(_class_re, line, 1)[0]
	regex.match(`^[^{]*\bimplements\s[^{]*\bCloneable\b`, _header(lines, i))
	count(_secret_fields(lines, i, cm[1], `\bstatic\b`)) > 0
	not _refuses_clone(_body_text(lines, i, cm[1]))
	finding := {
		"rule_id": metadata.id,
		"message": "Cloneable class holds a secret: clone() copies it without a constructor or access check. Do not implement Cloneable, or make clone() throw CloneNotSupportedException",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
