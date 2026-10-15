# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_767

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-767",
	"name": "Access to Critical Private Variable via Public Method",
	"description": "Reports a public no-argument Java method whose body returns, as is, a private field of the same file that holds key or secret material: a field typed PrivateKey, SecretKey, KeyPair, KeyStore or SecretKeySpec; a char[] or byte[] whose name says it is a password, secret, key, PIN or passphrase (the caller receives the live buffer and can read it or overwrite it, and the owner can no longer wipe it); or a String named for a secret, API key, private, signing, encryption or master key, client secret or passphrase. Making the field private achieved nothing once a public method hands it out. Every return statement in the body is read, so a getter that throws or returns early still counts. Not reported: public key bytes and key identifiers (publicKeyBytes, keyId), a getter that returns a copy (clone(), Arrays.copyOf), a method with @Override (a framework contract such as UserDetails.getPassword), private and package-private methods, String password and token fields (entity and DTO accessors, usually holding a hash or a value meant for the caller), returns of local variables, comments and test sources. Setters are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-767/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [767],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["critical-access-decl-non-final", "cwe-767"],
}

_private_field_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*private\s+(?:(?:static|final|transient|volatile)\s+)*([\w.]+(?:<[^;=()]*>)?(?:\s*\[\s*\])*)\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?;`

_public_getter_re := `^\s*public\s+(?:(?:static|final|synchronized)\s+)*[\w.]+(?:<[^()]*>)?(?:\s*\[\s*\])*\s+(\w+)\s*\(\s*\)\s*(?:throws\s+[\w., ]+)?\s*\{?`

_key_type(t) if regex.match(`^(?:java\.security\.|javax\.crypto\.(?:spec\.)?)?(?:PrivateKey|SecretKey|KeyPair|KeyStore|SecretKeySpec)$`, t)

_critical(t, _) if _key_type(t)

_critical(t, n) if {
	regex.match(`^(?:char|byte)\s*\[\s*\]$`, t)
	regex.match(`(?i)(password|passwd|passphrase|secret|key|pin$|seed)`, n)
	# public key material and key identifiers are not secrets
	not regex.match(`(?i)public|(?:key_?id|kid|keyIds?|fingerprint|thumbprint|hash|salt|iv|nonce|length|size)s?$`, n)
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_critical(t, n) if {
	regex.match(`^(?:java\.lang\.)?String$`, t)
	regex.match(`(?i)(secret|private_?key|api_?key|signing_?key|encryption_?key|master_?key|passphrase)`, n)
	not regex.match(`(?i)(name|label|url|uri|path|param|header|id|type)$`, n)
}

_overridden(lines, i) if {
	i > 0
	regex.match(`^\s*@Override\b`, lines[i - 1])
}

# The last line of a short method body: the declaration line itself when it
# closes there, otherwise the first closing-brace line within four lines.
_body_end(lines, i) := i if contains(lines[i], "}")

_body_end(lines, i) := e if {
	not contains(lines[i], "}")
	limit := min([count(lines) - 1, i + 12])
	ind := _indent(lines[i])
	closers := [k |
		some k in numbers.range(i + 1, limit)
		startswith(trim_space(lines[k]), "}")
		_indent(lines[k]) <= ind
	]
	e := min(array.concat([limit], closers))
}

# The bare identifiers returned by the return statements in the method body.
_returned(lines, i) := {name |
	end := _body_end(lines, i)
	some j in numbers.range(i, end)
	not helpers.is_comment_line(lines[j])
	m := regex.find_all_string_submatch_n(`\breturn\s+([^;]*);`, lines[j], 1)
	count(m) > 0
	expr := trim_space(m[0][1])
	mm := regex.find_all_string_submatch_n(`^(?:this\.)?([A-Za-z_]\w*)$`, expr, 1)
	count(mm) > 0
	name := mm[0][1]
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "private ")
	contains(content, "return")
	lines := split(content, "\n")
	fields := {name: t |
		some l in lines
		contains(l, "private ")
		m := regex.find_all_string_submatch_n(_private_field_re, l, 1)
		count(m) > 0
		t := trim_space(m[0][1])
		name := m[0][2]
		_critical(t, name)
	}
	count(fields) > 0
	some i, line in lines
	contains(line, "public ")
	not helpers.is_comment_line(line)
	regex.match(_public_getter_re, line)
	not _overridden(lines, i)
	some name in _returned(lines, i)
	fields[name]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Public method returns the private secret field '%s' itself; return a copy, a narrower view, or keep the secret inside the class", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
