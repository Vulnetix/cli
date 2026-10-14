package vulnetix.rules.vnx_java_019

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-019",
	"name": "Java hardcoded cryptographic key literal",
	"description": "A symmetric or signing key is written into the source and handed to a key API, so anyone with the jar can decrypt or forge what it protects. Reported: new SecretKeySpec(...) and new PBEKeySpec(...) whose key argument is a string literal (.getBytes()/.toCharArray()), a Base64/hex decode of a literal, or a byte-array literal; JJWT signWith(alg, key) and setSigningKey(key), auth0 Algorithm.HMAC256/384/512(key) and Keys.hmacShaKeyFor(key) with such a value; and the same calls given a String, byte[] or char[] variable or constant declared in the file with such a literal, directly or through one .getBytes() assignment. Not reported: keys read from the environment, a KeyStore, properties, Spring @Value injection, KeyGenerator or a method parameter; algorithm-name literals (\"AES\"); test sources; and the pattern in comments or string literals. Initialisation vectors are VNX-JAVA-020's concern.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-019/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [321],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["crypto", "hardcoded-key", "secrets", "java"],
}

_lit := `"(?:[^"\\]|\\.)+"`

# An expression whose value is fixed in the source: a non-empty string literal
# (optionally .getBytes()/.toCharArray()), a decode/encode of one, or a
# byte-array literal.
_literal_expr := concat("", [
	`^(`, _lit, `(\s*\.\s*(getBytes|toCharArray)\s*\([^)]*\))?`,
	`|[\w.()]*\.\s*(decode|decodeBase64|decodeHex|parseHexBinary|encode)\s*\(\s*`, _lit, `\s*(,[^)]*)?\)(\s*\.\s*(getBytes|toCharArray)\s*\([^)]*\))?`,
	`|(new\s+byte\s*\[\s*\]\s*)?\{\s*(\(byte\)\s*)?-?(0[xX][0-9a-fA-F]+|[0-9]+)`,
	`)\s*[,;)}]`,
])

_decl_re := `^\s*(?:(?:public|private|protected|static|final)\s+)*(?:String|byte\s*\[\s*\]|char\s*\[\s*\]|var)\s+([A-Za-z_]\w*)\s*=\s*(.*)$`

_strip_strings(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

# Names declared in this file with a literal value.
_lit_names(lines) := {m[1] |
	some l in lines
	contains(l, "=")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_decl_re, l, 1)
	regex.match(_literal_expr, trim_space(m[2]))
}

# One hop: byte[] kb = k.getBytes(...) where k holds a literal.
_hop_names(lines, base) := {m[1] |
	some l in lines
	contains(l, "getBytes")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_decl_re, l, 1)
	some h in regex.find_all_string_submatch_n(`^(?:this\.)?([A-Za-z_]\w*)\s*\.\s*(?:getBytes|toCharArray)\s*\(`, trim_space(m[2]), 1)
	h[1] in base
}

_names(lines) := n | _hop_names(lines, n) if n := _lit_names(lines)

# Sinks: the text that follows is the key argument.
_sink_re := `new\s+(?:SecretKeySpec|PBEKeySpec)\s*\(\s*|\.\s*signWith\s*\(\s*[\w.]+\s*,\s*|\.\s*setSigningKey\s*\(\s*|\bAlgorithm\s*\.\s*HMAC(?:256|384|512)\s*\(\s*|\bKeys\s*\.\s*hmacShaKeyFor\s*\(\s*`

_name_arg := `^(?:this\.)?([A-Za-z_]\w*)\s*(?:\.\s*(?:getBytes|toCharArray)\s*\([^)]*\)\s*)?[,)]`

_stmt(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 2]))])

_hard_coded(lines, rest) if regex.match(_literal_expr, rest)

_hard_coded(lines, rest) if {
	some m in regex.find_all_string_submatch_n(_name_arg, rest, 1)
	m[1] in _names(lines)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`SecretKeySpec|PBEKeySpec|signWith|setSigningKey|HMAC(256|384|512)|hmacShaKeyFor`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`SecretKeySpec|PBEKeySpec|signWith|setSigningKey|HMAC(256|384|512)|hmacShaKeyFor`, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _strip_strings(line))
	stmt := regex.replace(_stmt(lines, i), `//[^"\n]*$`, "")
	some m in regex.find_all_string_submatch_n(concat("", [`(?:`, _sink_re, `)(.*)`]), stmt, -1)
	rest := m[1]
	_hard_coded(lines, rest)
	finding := {
		"rule_id": metadata.id,
		"message": "Cryptographic key is hardcoded in the source; load it from a key store, KMS or secrets manager at runtime",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
