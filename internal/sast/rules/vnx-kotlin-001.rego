package vulnetix.rules.vnx_kotlin_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-KOTLIN-001",
	"name": "Kotlin block cipher in ECB mode",
	"description": "Kotlin code (.kt, .kts) creates a javax.crypto Cipher in Electronic Codebook mode with any block cipher (AES, DES, DESede/TripleDES, Blowfish, SM4, Camellia and the like), so equal plaintext blocks encrypt to equal ciphertext and nothing detects tampering. Reported: Cipher.getInstance with an X/ECB/... transformation (with or without a provider, across a line break, in lower case); with a bare block-cipher name (\"AES\", \"DES\", \"DESede\", \"Blowfish\", KeyProperties.KEY_ALGORITHM_AES or KEY_ALGORITHM_3DES), which names no mode and gets the provider default ECB; with a string template or concatenation that puts ECB in the mode position (\"$ALGORITHM/ECB/...\", \"${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_ECB}/...\"); and with a constant anywhere in the file, companion objects included, whose literal value is one of those. Not reported: GCM, CBC, CTR and other modes, stream and AEAD ciphers (ChaCha20), RSA/ECB/... (RSA's mode name, not block ECB, also through a constant), KeyGenerator/SecretKeySpec/Mac.getInstance, a transformation passed in as a parameter or read from configuration, ECB literals that never reach Cipher.getInstance (a deny list), comments and strings, and Java files. AES-ECB is also reported by VNX-ANDROID-007.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-001/",
	"languages": ["kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-463"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "ecb", "kotlin"],
}

_kotlin(path) if endswith(path, ".kt")

_kotlin(path) if endswith(path, ".kts")

_code(s) := regex.replace(s, `"(\\.|[^"\\])*"`, `""`)

_ci_re := `\bCipher\s*\.\s*getInstance\s*\(`

_first_arg(lines, i) := trim_space(ms[0][1]) if {
	text := concat(" ", array.slice(lines, i, min([count(lines), i + 3])))
	ms := regex.find_all_string_submatch_n(`\bCipher\s*\.\s*getInstance\s*\(\s*((?:"(?:[^"\\]|\\.)*"|[\w.$]+|\s*\+\s*)+)`, text, 1)
	count(ms) > 0
}

_block := `(AES(_\d+)?|DES|DESede|TripleDES|3DES|Blowfish|RC2|RC5|SM4|Camellia|ARIA|SEED|Twofish|Serpent|CAST5|CAST6|IDEA|GOST28147|XTEA|Rijndael|Noekeon|Skipjack)`

_ecb(a) if regex.match(`(?i)(^|[^a-z0-9])ECB([^a-z0-9]|$)`, a)

_rsa(a) if regex.match(`(?i)(^|[^a-z])(RSA|ECIES)([^a-z]|$)`, a)

_literals(lines) := {[m[1], m[2]] |
	some l in lines
	contains(l, "\"")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"([^"$]*)"\s*;?\s*$`, l, 1)
}

_rsa_names(lits) := {n | some [n, v] in lits; _rsa(v)}

_ecb_names(lits) := {n |
	some [n, v] in lits
	not _rsa(v)
	regex.match(concat("", [`(?i)^([\w-]+/ECB(/.*)?|`, _block, `)$`]), v)
}

_names_in(a) := {m[1] | some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)`, a, -1)}

# Explicit ECB in the mode position, unless the algorithm is RSA.
_ecb_cipher(a, lits) if {
	_ecb(a)
	not _rsa(a)
	every n in _names_in(a) {
		not n in _rsa_names(lits)
	}
}

# A bare block cipher: the provider default mode is ECB.
_ecb_cipher(a, _) if regex.match(concat("", [`(?i)^("`, _block, `"|(KeyProperties\.)?KEY_ALGORITHM_(AES|3DES))$`]), a)

# A constant holding one of the above.
_ecb_cipher(a, lits) if {
	ms := regex.find_all_string_submatch_n(`^(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)$`, a, 1)
	count(ms) > 0
	ms[0][1] in _ecb_names(lits)
}

findings contains finding if {
	some path, content in input.file_contents
	_kotlin(path)
	contains(content, "getInstance")
	contains(content, "Cipher")
	lines := split(content, "\n")
	lits := _literals(lines)
	some i, line in lines
	contains(line, "getInstance")
	not helpers.is_comment_line(line)
	regex.match(_ci_re, _code(line))
	a := _first_arg(lines, i)
	_ecb_cipher(a, lits)
	finding := {
		"rule_id": metadata.id,
		"message": "Cipher.getInstance() selects ECB mode (explicitly, or by naming a block cipher with no mode, which the provider completes as ECB): identical plaintext blocks produce identical ciphertext and tampering goes undetected. Use AES/GCM/NoPadding with a fresh random 12-byte IV per message",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
