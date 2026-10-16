# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_499

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-499",
	"name": "Serializable Class Containing Sensitive Data",
	"description": "A Java class that implements Serializable (the clause may span lines) declares a non-transient, non-static field holding a secret: a String, char[], byte[] or CharSequence whose name says password, passwd, passphrase, pwd, pin, secret, API key, private key, an access/refresh/auth/session/bearer/id/csrf token, credential, credit card/card number, CVV or SSN, or a field of type PrivateKey, SecretKey, SecretKeySpec, KeyPair, KeyStore or Key. Serialising the object writes the secret into the byte stream (session stores, caches, files, RMI). Reported on the field. Not reported: transient and static fields (PASSWORD_PARAM constants), names that describe the secret rather than hold it (passwordPolicy, secretName, tokenEndpoint) or non-text types (int passwordLength), classes that control their serial form (writeObject, writeReplace, serialPersistentFields, Externalizable), classes that are not Serializable, test code, comments and string literals. Classes that become Serializable only through a superclass are not resolved.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-499/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [499],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["serializable-sensitive", "cwe-499"],
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
		some k in helpers.span(i + 1, lim - 1)
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

_controls_form(text) if regex.match(`\b(?:writeObject|writeReplace)\s*\(|serialPersistentFields|\bExternalizable\b`, text)

_message(name) := sprintf("Serializable class stores '%s' in its serial form; mark the field transient or define writeObject/writeReplace so the secret is not written out", [name])

_finding(path, k, line, name) := {
	"rule_id": metadata.id,
	"message": _message(name),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": k + 1,
	"snippet": line,
}

_java_files contains [path, content] if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "Serializable")
	not helpers.is_test_path(path)
}

# A field of a class that implements Serializable.
findings contains finding if {
	some [path, content] in _java_files
	regex.match(`\bclass\s+\w+[^{;]*\bimplements\s[^{;]*\bSerializable\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "class")
	not helpers.is_comment_line(line)
	cm := regex.find_all_string_submatch_n(_class_re, line, 1)[0]
	regex.match(`^[^{]*\bimplements\s[^{]*\bSerializable\b`, _header(lines, i))
	not _controls_form(_body_text(lines, i, cm[1]))
	some [k, name] in _secret_fields(lines, i, cm[1], `\b(?:static|transient)\b`)
	finding := _finding(path, k, lines[k], name)
}

# A component of a record that implements Serializable: every component is a
# serialised field.
findings contains finding if {
	some [path, content] in _java_files
	regex.match(`\brecord\s+\w+[^{;]*\bimplements\s[^{;]*\bSerializable\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "record")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:public|protected|private|static|final)\s+)*record\s+\w+(?:<[^>]*>)?\s*\(([^)]*)\)\s*implements\s[^{]*\bSerializable\b`, _code(line), 1)[0]
	not _controls_form(_body_text(lines, i, _lead(line)))
	some comp in split(m[1], ",")
	parts := regex.find_all_string_submatch_n(`(String|char\s*\[\s*\]|byte\s*\[\s*\]|CharSequence|SecretKey|SecretKeySpec|PrivateKey|Key|KeyPair|KeyStore)\s+(\w+)\s*$`, trim_space(regex.replace(comp, `@\w+(?:\([^)]*\))?`, "")), 1)[0]
	_sensitive(regex.replace(parts[1], `\s+`, ""), parts[2])
	finding := _finding(path, i, line, parts[2])
}
