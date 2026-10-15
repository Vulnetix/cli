package vulnetix.rules.vnx_android_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-ANDROID-007",
	"name": "AES cipher in ECB mode (Java/Kotlin)",
	"description": "A javax.crypto Cipher is created for AES in Electronic Codebook mode, which encrypts equal 16-byte blocks to equal ciphertext and carries no integrity check. Reported, in Java and Kotlin: Cipher.getInstance with an AES/ECB/... transformation (also AES_128/AES_256 and lower case, with or without a provider argument); with bare \"AES\" or KeyProperties.KEY_ALGORITHM_AES, which names no mode and gets the provider default AES/ECB/PKCS5Padding; with KeyProperties.KEY_ALGORITHM_AES + \"/\" + KeyProperties.BLOCK_MODE_ECB concatenations or Kotlin string templates; and with a constant (anywhere in the file, including a companion object below the call) whose literal value is one of those. Not reported: GCM, CBC, CTR and other modes, AESWrap, RSA/ECB/... (RSA's mode name, not block ECB), KeyGenerator/SecretKeySpec/Mac.getInstance(\"AES\"), a transformation read from configuration or passed in as a parameter, an ECB literal that never reaches Cipher.getInstance (a deny list), comments and strings. ECB with DES, 3DES or Blowfish is left to the broken-cipher rules and, in Kotlin, VNX-KOTLIN-001.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-007/",
	"languages": ["java", "kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["android", "weak-crypto", "aes-ecb", "mobile-security"],
}

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".kt")

_lang(path) if endswith(path, ".kts")

_code(s) := regex.replace(s, `"(\\.|[^"\\])*"`, `""`)

_ci_re := `\bCipher\s*\.\s*getInstance\s*\(`

# The first argument of the Cipher.getInstance call on line i: string
# literals (Kotlin templates included), names, and + concatenation, possibly
# continued on the next lines.
_first_arg(lines, i) := trim_space(ms[0][1]) if {
	text := concat(" ", array.slice(lines, i, min([count(lines), i + 3])))
	ms := regex.find_all_string_submatch_n(`\bCipher\s*\.\s*getInstance\s*\(\s*((?:"(?:[^"\\]|\\.)*"|[\w.$]+|\s*\+\s*)+)`, text, 1)
	count(ms) > 0
}

_aes(a) if regex.match(`(?i)(^|[^a-z0-9])AES([^a-z]|$)`, a)

_ecb(a) if regex.match(`(?i)(^|[^a-z0-9])ECB([^a-z0-9]|$)`, a)

_rsa(a) if regex.match(`(?i)(^|[^a-z])(RSA|ECIES)([^a-z]|$)`, a)

# Literal values assigned to a single name in this file.
_literals(lines) := {[m[1], m[2]] |
	some l in lines
	contains(l, "\"")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"([^"$]*)"\s*;?\s*$`, l, 1)
}

_aes_names(lits) := {n | some [n, v] in lits; regex.match(`(?i)^AES(_\d+)?(/.*)?$`, v)}

_ecb_names(lits) := {n | some [n, v] in lits; regex.match(`(?i)^AES(_\d+)?(/ECB(/.*)?)?$`, v)}

_names_in(a) := {m[1] | some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)`, a, -1)}

# Explicit ECB with AES in the argument itself or through an AES constant.
_aes_ecb(a, _) if {
	_ecb(a)
	not _rsa(a)
	_aes(a)
}

_aes_ecb(a, lits) if {
	_ecb(a)
	not _rsa(a)
	not _aes(a)
	some n in _names_in(a)
	n in _aes_names(lits)
}

# No mode: the provider default is ECB.
_aes_ecb(a, _) if regex.match(`(?i)^("AES"|(KeyProperties\.)?KEY_ALGORITHM_AES)$`, a)

# A constant holding one of the above.
_aes_ecb(a, lits) if {
	ms := regex.find_all_string_submatch_n(`^(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)$`, a, 1)
	count(ms) > 0
	ms[0][1] in _ecb_names(lits)
}

# A constant built by concatenation: MODE = ALGO + "/ECB/PKCS5Padding".
_aes_ecb(a, lits) if {
	ms := regex.find_all_string_submatch_n(`^(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)$`, a, 1)
	count(ms) > 0
	n := ms[0][1]
	some [n2, e] in lits
	n2 == concat("", ["+", n])
	_ecb(e)
	not _rsa(e)
	some x in _names_in(regex.replace(e, `"[^"]*"`, ""))
	x in _aes_names(lits)
}

# Concatenated constants, keyed "+NAME" so they never mix with literals.
_concat_lits(lines) := {[concat("", ["+", m[1]]), m[2]] |
	some l in lines
	contains(l, "+")
	contains(l, "ECB")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*((?:"[^"$]*"|[A-Za-z_][\w.]*)(?:\s*\+\s*(?:"[^"$]*"|[A-Za-z_][\w.]*))+)\s*;?\s*$`, l, 1)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "getInstance")
	regex.match(`(?i)aes`, content)
	lines := split(content, "\n")
	lits := _literals(lines) | _concat_lits(lines)
	some i, line in lines
	contains(line, "getInstance")
	not helpers.is_comment_line(line)
	regex.match(_ci_re, _code(line))
	a := _first_arg(lines, i)
	_aes_ecb(a, lits)
	finding := {
		"rule_id": metadata.id,
		"message": "AES is used in ECB mode (explicitly, or by naming no mode and getting the provider default): equal plaintext blocks encrypt to equal ciphertext and nothing detects tampering. Use AES/GCM/NoPadding with a fresh 12-byte IV per message",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
