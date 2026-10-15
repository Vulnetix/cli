# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_929

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-929",
	"name": "Broken hash algorithm (MD5, MD2, MD4, SHA-1) in Java or Kotlin",
	"description": "CWE-929 is an OWASP Top Ten 2013 category with no code shape of its own; this rule reports the concrete Java/Kotlin signal it was generated for, a collision-broken digest: MessageDigest.getInstance(\"MD5\"/\"MD2\"/\"MD4\"/\"SHA-1\"/\"SHA1\"/\"SHA\"), with the argument possibly on the next line, the same name passed through a String constant assigned in the same file or as commons-codec MessageDigestAlgorithms.MD2/MD5/SHA_1, Apache commons-codec DigestUtils.md5/md5Hex/sha1/sha1Hex/sha/shaHex/md2 (and getMd5Digest/getSha1Digest), Spring DigestUtils.md5Digest/md5DigestAsHex, and Guava Hashing.md5()/Hashing.sha1(). Not reported: SHA-2 and SHA-3 digests, algorithm names in comments and strings, and digests whose surrounding code names a non-security purpose (an ETag, checksum, CRC, cache key, fingerprint, de-duplication, a Gravatar URL or the RFC 6455 WebSocket accept key). Whether the digest protects a password or signature is not decided here; VNX-327 reports that narrower case.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-929/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [929],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["weak-hash-mobile", "crypto", "cwe-929"],
}

_ext(path) if endswith(path, ".java")

_ext(path) if endswith(path, ".kt")

_weak := `"(?i:md5|md2|md4|sha-?1|sha)"`

_md := `\bMessageDigest\s*\.\s*getInstance\s*\(\s*`

_sink_re := concat("|", [
	concat("", [_md, _weak]),
	`\bDigestUtils\s*\.\s*((md2|md5|sha1|sha)(Hex)?|get(Md2|Md5|Sha1|Sha)Digest)\s*\(`,
	`\bHashing\s*\.\s*(md5|sha1)\s*\(`,
	`\bDigestUtils\s*\.\s*md5Digest(AsHex)?\s*\(`,
	concat("", [`(\bMessageDigest\s*\.\s*getInstance|\bDigestUtils\s*\.\s*getDigest)\s*\(\s*`, `MessageDigestAlgorithms\s*\.\s*(MD2|MD5|SHA_1)\b`]),
])

_gate_re := `(?i)"(md5|md2|md4|sha-?1|sha)"|DigestUtils\s*\.\s*(md|sha1?\b|sha1?hex|getmd|getsha)|Hashing\s*\.\s*(md5|sha1)\s*\(|MessageDigestAlgorithms\s*\.\s*(MD2|MD5|SHA_1)\b`

# The call joined with the next line when its argument starts there.
_call_text(line, _) := line if not regex.match(`getInstance\s*\(\s*$`, line)

_call_text(line, next) := concat(" ", [line, trim_space(next)]) if regex.match(`getInstance\s*\(\s*$`, line)

_next(lines, i) := lines[i + 1] if i + 1 < count(lines)

_next(lines, i) := "" if i + 1 >= count(lines)

_weak_consts(lines) := {m[0][1] |
	some l in lines
	contains(l, "\"")
	m := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*(:\s*String\s*)?=\s*`, _weak]), l, 1)
	count(m) > 0
}

_hit(line, _) if regex.match(_sink_re, line)

_hit(line, consts) if {
	count(consts) > 0
	m := regex.find_all_string_submatch_n(concat("", [_md, `([A-Za-z_][\w.]*)\s*[,)]`]), line, 1)
	count(m) > 0
	parts := split(m[0][1], ".")
	parts[count(parts) - 1] in consts
}

_non_security_re := `(?i)(etag|checksum|\bcrc|websocket|content-?md5|cache_?key|fingerprint|dedup|gravatar)`

_non_security(lines, i) if {
	regex.match(_non_security_re, helpers.code_window(lines, i, 3, 1))
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`getInstance|DigestUtils|Hashing`, content)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	consts := _weak_consts(lines)
	some i, line in lines
	regex.match(`getInstance|DigestUtils|Hashing`, line)
	not helpers.is_comment_line(line)
	_hit(_call_text(line, _next(lines, i)), consts)
	not _non_security(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Collision-broken hash (MD5, MD2, MD4 or SHA-1): do not use it for passwords, tokens or signatures. Use SHA-256 or better, and a password KDF (bcrypt, scrypt, Argon2, PBKDF2) for passwords",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
