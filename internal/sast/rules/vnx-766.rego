# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_766

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-766",
	"name": "Critical Data Element Declared Public",
	"description": "Reports a Java class field that is declared public and holds secret material: a non-final public field of a string-like or credential type (String, char[], byte[], CharSequence, Map, *Credentials) whose name says it is a password, secret, API key, private key, token or credential; any public field typed PrivateKey, SecretKey, KeyPair, KeyStore or SecretKeySpec; and a public final char[] or byte[] secret (final freezes the reference, not the contents). Any class can then read or overwrite the value. Not reported: private, protected and package-private fields, public final String constants (usually parameter or header names), non-secret types (boolean, int, Instant), names that describe metadata about a secret (passwordHint, tokenUrl, tokenEndpoint, secretQuestionLabel, tokenType), and words that only begin with a secret word (secretary, tokenizer), local variables, comments, string literals and test sources.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-766/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [766],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["critical-data-elem-declared-public", "cwe-766"],
}

# A field declaration: optional annotations, `public`, other modifiers, a
# type, a name, an optional initialiser, and the terminating semicolon. A
# method has `(` straight after its name, so it never matches.
_field_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*public\s+((?:(?:static|final|transient|volatile)\s+)*)([\w.]+(?:<[^;=()]*>)?(?:\s*\[\s*\])*)\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?;`

_secret_name(n) if {
	# the secret word ends at a camelCase, snake_case or name boundary, so
	# secretary and tokenizer are not secrets
	regex.match(`(?i:password|passwd|passphrase|secret|api_?key|access_?key|private_?key|signing_?key|encryption_?key|master_?key|token|credential)s?(?:[A-Z_0-9]|$)`, n)
	not regex.match(`(?i)(hint|label|url|uri|path|param|name|field|header|length|prompt|pattern|regex|policy|expiry|expires|expiration|count|type|question|id|ttl|timeout|endpoint|link|host|server|issuer|provider|file|location|format|mode|algorithm|enabled|required)s?$`, n)
}

_stringish(t) if regex.match(`^(?:java\.lang\.)?(?:String|CharSequence|StringBuilder|StringBuffer)$`, t)

_stringish(t) if _array(t)

_stringish(t) if regex.match(`^(?:Map|HashMap|Properties|ConcurrentHashMap)\b`, t)

_stringish(t) if regex.match(`Credentials?$`, t)

_key_type(t) if regex.match(`^(?:java\.security\.|javax\.crypto\.(?:spec\.)?)?(?:PrivateKey|SecretKey|KeyPair|KeyStore|SecretKeySpec)$`, t)

_array(t) if regex.match(`^(?:char|byte)\s*\[\s*\]$`, t)

_exposed(_, t, _) if _key_type(t)

_exposed(mods, t, n) if {
	not contains(mods, "final")
	_stringish(t)
	_secret_name(n)
}

_exposed(mods, t, n) if {
	contains(mods, "final")
	_array(t)
	_secret_name(n)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "public ")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "public ")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_field_re, line, 1)
	count(m) > 0
	_exposed(m[0][1], trim_space(m[0][2]), m[0][3])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Field '%s' holds secret material and is declared public; make it private and expose at most a narrow, copying accessor", [m[0][3]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
