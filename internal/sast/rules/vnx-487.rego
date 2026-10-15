# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_487

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-487",
	"name": "Reliance on Package-level Scope",
	"description": "A credential is held in a Java field with no access modifier, so the only thing protecting it is package scope: a field of a top-level class, declared at member level without private/protected/public, that is either a key type (SecretKey, PrivateKey, Key, KeyPair, Credentials, any name) or a String/char[]/byte[] whose name says it is a password, passphrase, secret, API key, token, credential or private key. Java packages are open (any class that declares the same package, or a jar on the class path that splits it, can read the field), so this is not access control. Not reported: private, protected and public fields (public exposure is VNX-493), fields of an interface (implicitly public), injected fields carrying an annotation, constants that name a parameter, header, field, attribute or length rather than holding a value (PASSWORD_PARAM, TOKEN_HEADER), local variables, nested classes, test code and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-487/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [487],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["package-level-scope", "access-modifier", "credentials", "cwe-487"],
}

# A member-level field with no access modifier, of a credential-capable type.
_field_re := `^([ \t]+)(?:(?:static|final|transient|volatile)\s+)*(String|char\s*\[\]|byte\s*\[\]|SecretKey|SecretKeySpec|PrivateKey|Key|KeyPair|Credentials?|PasswordAuthentication)\s+(\w+)\s*(?:=[^=]|;)`

_key_types := {"SecretKey", "SecretKeySpec", "PrivateKey", "Key", "KeyPair", "Credentials", "Credential", "PasswordAuthentication"}

_secret_name_re := `(?i)password|passwd|passphrase|secret|api_?key|private_?key|token|credential`

# Names that describe a credential's label rather than hold one: the last
# word (after `_` or a camel-case hump) is PARAM, FIELD, HEADER, NAME, ...
_label_name_re := `(?:_(?i:params?|parameters?|fields?|headers?|attrs?|attributes?|label|names?|prefix|suffix|pattern|regex|url|uri|path|length|len|min|max|size|type|kind|placeholder|hint|prompt|keyname|property|prop|env|var|column|col|msg|message|error|cookie|query|endpoint|format)|[a-z0-9](?:Params?|Parameters?|Fields?|Headers?|Attrs?|Attributes?|Label|Names?|Prefix|Suffix|Pattern|Regex|Url|Uri|URL|URI|Path|Length|Len|Min|Max|Size|Type|Kind|Placeholder|Hint|Prompt|Property|Prop|Env|Var|Column|Col|Msg|Message|Error|Cookie|Query|Endpoint|Format))$`

_credential(type, name) if {
	_key_types[type]
	not regex.match(_label_name_re, name)
}

_credential(type, name) if {
	not _key_types[type]
	regex.match(_secret_name_re, name)
	not regex.match(_label_name_re, name)
}

# A key named for its algorithm or purpose (hmacKey, signingKey, aes_key);
# raw byte[]/char[] key material named only *Key also counts.
_key_name_re := `(?i)(?:hmac|aes|des|rsa|signing|sign|encryption|encrypt|decrypt|crypt|cipher|master|private|secret|session|access|auth|mac|wrapping|wrap|jwt)_?key$`

_credential(type, name) if {
	not _key_types[type]
	regex.match(_key_name_re, name)
	not regex.match(_label_name_re, name)
}

_credential(type, name) if {
	regex.match(`^(?:char|byte)`, type)
	_bare_key(name)
}

_bare_key(name) if regex.match(`(?:^(?i:key)|[a-z0-9]Key|_(?i:key))$`, name)

# A String named only key/*Key is a key only in a file that does cryptography
# with it (javax.crypto, SecretKeySpec, Cipher); elsewhere it is a map key.
_crypto_file(content) if contains(content, "javax.crypto")

_crypto_file(content) if contains(content, "SecretKeySpec")

_crypto_file(content) if contains(content, "Cipher.getInstance")

_crypto_string_key(content, type, name) if {
	type == "String"
	_bare_key(name)
	not regex.match(_label_name_re, name)
	_crypto_file(content)
}

_credential_in(_, type, name) if _credential(type, name)

_credential_in(content, type, name) if _crypto_string_key(content, type, name)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_decl_re := `^(?:\S.*\s)?@?(?:class|interface|enum|record)\s+\w+`

# The nearest top-level type declaration above line i.
_top_decl(lines, i) := d if {
	decls := [j |
		some j in numbers.range(0, i)
		regex.match(_decl_re, lines[j])
		not helpers.is_comment_line(lines[j])
	]
	count(decls) > 0
	d := decls[count(decls) - 1]
}

# Line i is a member of a top-level class (not an interface or annotation
# type, whose fields are public): it sits at the indent of the first code
# line of that class's body.
_class_member(lines, i, ind) if {
	d := _top_decl(lines, i)
	not regex.match(`(?:^|\s)@?interface\s`, lines[d])
	body := [j |
		some j in numbers.range(d + 1, min([i, d + 40]))
		trim_space(lines[j]) != ""
		trim_space(lines[j]) != "{"
		not helpers.is_comment_line(lines[j])
	]
	count(body) > 0
	_indent(lines[body[0]]) == ind
}

_annotated(lines, i) if {
	i > 0
	startswith(trim_space(lines[i - 1]), "@")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?m)^[ \t]+(?:(?:static|final|transient|volatile)\s+)*(?:String|char\s*\[\]|byte\s*\[\]|SecretKey|SecretKeySpec|PrivateKey|Key|KeyPair|Credentials?|PasswordAuthentication)\s+\w+\s*[=;]`, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(_field_re, line, 1)
	count(m) > 0
	name := m[0][3]
	_credential_in(content, m[0][2], name)
	not _annotated(lines, i)
	_class_member(lines, i, count(m[0][1]))
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Credential field '%s' has package-private access: any class that declares this package can read it. Make it private and expose only what callers need", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
