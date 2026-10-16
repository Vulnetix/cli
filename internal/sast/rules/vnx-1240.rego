# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1240

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1240",
	"name": "Use of a Cryptographic Primitive with a Risky Implementation",
	"description": "A Java javax.crypto.Cipher is created for a block cipher in ECB mode, which encrypts equal plaintext blocks to equal ciphertext blocks and so leaks the structure of the data and allows blocks to be cut, replayed and reordered. Reported: Cipher.getInstance() whose transformation names ECB for a block cipher (\"AES/ECB/PKCS5Padding\", \"DESede/ECB/NoPadding\", any case, with or without a provider argument), a bare block-cipher name (\"AES\", \"DES\", \"DESede\", \"Blowfish\", \"RC2\" and the like) for which the JCE provider default is ECB, the transformation written on the line after the opening parenthesis, and a Cipher.getInstance(NAME) whose NAME is a constant assigned such a transformation in the same file. Not reported: GCM, CCM, CBC, CTR and other modes, ChaCha20, AESWrap, RSA/ECB/... (RSA has no chaining; padding is judged by VNX-780), KeyGenerator.getInstance(\"AES\") and SecretKeySpec(..., \"AES\"), a transformation passed in a variable whose value is not visible in the file, the text in comments or inside other string literals, and every call VNX-CRYPTO-003 (AES in ECB mode, CWE-327) reports: an explicit /ECB/ transformation, a bare block-cipher name, a constant or a getProperty default holding one, and a call split after getInstance( (reported there on the call line). Those are reported by VNX-CRYPTO-003, so a Java ECB cipher is one finding rather than two. What that rule does not report stays here: a mode concatenated onto the algorithm (alg + \"/ECB/PKCS5Padding\"), a getOrDefault default, and ECB in test sources, which VNX-CRYPTO-003 leaves out.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1240/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1240],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["risky-primitive", "ecb", "java", "cwe-1240"],
}

# A transformation that selects ECB for a block cipher, explicitly or by the
# provider default for a bare algorithm name.
_ecb(t) if {
	regex.match(`(?i)^[a-z0-9_-]+/ECB(/|$)`, t)
	not regex.match(`(?i)^(RSA|EC|ELGAMAL)`, t)
}

_ecb(t) if regex.match(`(?i)^(AES|AES_(128|192|256)|DES|DESede|TripleDES|3DES|Blowfish|RC2|RC5|IDEA|SEED|ARIA|Camellia|SM4|CAST5|CAST6|Twofish|Serpent)$`, t)

_call_lit_re := `\bCipher\s*\.\s*getInstance\s*\(\s*"([^"\\]*)"\s*[,)]`

_call_name_re := `\bCipher\s*\.\s*getInstance\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]`

# NAME = "AES/ECB/..."; or NAME = props.getProperty("key", "AES/ECB/...");
# (the literal default of a configuration lookup).
_const_re := `\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[\w.]+\s*\.\s*(?:getProperty|getOrDefault)\s*\(\s*"[^"]*"\s*,\s*)?"([^"\\]*)"\s*\)?\s*;`

_msg :="Cipher in ECB mode (explicit, or the provider default for a bare block-cipher name): equal plaintext blocks encrypt identically. Use an authenticated mode such as \"AES/GCM/NoPadding\" with a unique IV"

_report(lines, i) if {
	m := regex.find_all_string_submatch_n(_call_lit_re, lines[i], 1)
	count(m) > 0
	_ecb(m[0][1])
}

# Cipher.getInstance(alg + "/ECB/PKCS5Padding"): the mode is a concatenated literal.
_report(lines, i) if regex.match(`(?i)\bCipher\s*\.\s*getInstance\s*\([^;]*\+\s*"/ECB(?:/[^"]*)?"`, lines[i])

# Cipher.getInstance(
#     "AES/ECB/NoPadding")
_report(lines, i) if {
	m := regex.find_all_string_submatch_n(`^\s*"([^"\\]*)"\s*[,)]`, lines[i], 1)
	count(m) > 0
	_ecb(m[0][1])
	i > 0
	regex.match(`\bCipher\s*\.\s*getInstance\s*\(\s*$`, lines[i - 1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "getInstance")
	contains(content, "Cipher")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "\"")
	not helpers.is_comment_line(line)
	_report(lines, i)
	not _vnx003_reports(path, content, lines, i)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "Cipher")
	contains(content, "getInstance")
	lines := split(content, "\n")

	# Constants in the file that hold an ECB transformation.
	consts := {n |
		some l in lines
		contains(l, "\"")
		contains(l, "=")
		not helpers.is_comment_line(l)
		m := regex.find_all_string_submatch_n(_const_re, l, 1)
		count(m) > 0
		_ecb(m[0][2])
		n := m[0][1]
	}
	count(consts) > 0
	some i, line in lines
	contains(line, "getInstance")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_call_name_re, line, 1)
	count(m) > 0
	m[0][1] in consts
	not _vnx003_reports(path, content, lines, i)
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── ECB that VNX-CRYPTO-003 reports is left to it ────────────────────────
# VNX-CRYPTO-003 (AES in ECB mode, CWE-327) reads the same Java forms: an
# explicit /ECB/ transformation, a bare block-cipher name, a constant or a
# getProperty default holding one. A call it reports is one finding, so this
# rule does not report it again, neither on the same line nor, for a call split
# after "getInstance(", on the literal's line below the call it reports. The
# test is VNX-CRYPTO-003's own Java condition, so every line this rule no
# longer reports is still reported there. What it does not report stays here:
# a mode concatenated on ("alg + \"/ECB/...\""), a getOrDefault default, and
# ECB in test sources, which that rule leaves out.

_vnx003_reports(path, content, lines, i) if _v003_line(path, content, lines, i)

_vnx003_reports(path, content, lines, i) if {
	i > 0
	regex.match(`\bCipher\s*\.\s*getInstance\s*\(\s*$`, lines[i - 1])
	_v003_line(path, content, lines, i - 1)
}

_v003_ecb_lit := "['\"`](?i:[a-z0-9]+(?:-[a-z0-9]+)*-ecb|[a-z0-9]+/ecb(?:/[a-z0-9]+)?|ecb)['\"`]"

_v003_aes_default_lit := `"(?i:aes(?:_(?:128|192|256))?|des|desede|tripledes|blowfish)"`

_v003_code(line) := c if {
	s0 := regex.replace(line, `(?i)['"](?:rsa|ecies|elgamal)/ecb/[^'"]*['"]`, `""`)
	s := regex.replace(s0, _v003_ecb_lit, "__ECB__")
	s2 := regex.replace(s, _v003_aes_default_lit, "__AESDEF__")
	t := regex.replace(s2, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)
	c := regex.replace(t, `//.*$`, "")
}

_v003_ecb_value := `(?i:[a-z0-9]+/ecb/[a-z0-9]+|[a-z0-9]+/ecb|aes|des|desede|tripledes|blowfish)`

_v003_vars(content) := literal | defaults if {
	literal := {m[1] |
		some m in regex.find_all_string_submatch_n(concat("", [`\b(\w+)\s*=\s*"`, _v003_ecb_value, `"\s*[;,)]`]), content, -1)
		not regex.match(`(?i)=\s*"(?:rsa|ecies|elgamal)/`, m[0])
	}
	defaults := {m[1] |
		some m in regex.find_all_string_submatch_n(concat("", [`\b(\w+)\s*=\s*[\w.]*getProperty\s*\(\s*"([^"]*)"\s*,\s*"`, _v003_ecb_value, `"\s*\)\s*[;,)]`]), content, -1)
		not _v003_overridden(m[2])
	}
}

_v003_props := {[m[1], m[2]] |
	some p, c in input.file_contents
	endswith(p, ".properties")
	some m in regex.find_all_string_submatch_n(`(?m)^[ \t]*([\w.\-]+)[ \t]*[=:][ \t]*([^\s#]+)`, c, -1)
}

_v003_overridden(key) if {
	some kv in _v003_props
	kv[0] == key
	not regex.match(concat("", [`^`, _v003_ecb_value, `$`]), kv[1])
}

_v003_may(line) if {
	l := lower(line)
	some t in {"ecb", "getinstance"}
	contains(l, t)
}

_v003_may(line) if endswith(trim_right(line, " \t\r"), "(")

_v003_may(line) if endswith(trim_right(line, " \t\r"), ",")

_v003_hit(_, _, code, _) if regex.match(`\bCipher\.getInstance\s*\(\s*(?:__ECB__|__AESDEF__\s*[,)])`, code)

_v003_hit(_, _, code, content) if {
	some n in _v003_vars(content)
	regex.match(concat("", [`\bCipher\.getInstance\s*\(\s*`, n, `\s*[,)]`]), code)
}

_v003_hit(lines, i, code, _) if {
	regex.match(`\bCipher\.getInstance\s*\(\s*$`, code)
	end := min([count(lines) - 1, i + 3])
	i + 1 <= end
	rest := concat(" ", [_v003_code(lines[k]) | some k in numbers.range(i + 1, end); not helpers.is_comment_line(lines[k])])
	regex.match(`^[^;]*?(?:__ECB__|^\s*__AESDEF__\s*[,)])`, rest)
}

_v003_excluded(code) if regex.match(`[=!]==?\s*[\w.:]*(?:MODE_ECB|mode\.ECB)\b`, code)

_v003_excluded(code) if regex.match(`(?:MODE_ECB|mode\.ECB)\s*[=!]==?`, code)

_v003_line(path, content, lines, i) if {
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?i)ecb|"(?:aes(?:_\d+)?|des|desede|tripledes|blowfish)"`, content)
	line := lines[i]
	_v003_may(line)
	count(line) < 1000
	not helpers.is_comment_line(line)
	code := _v003_code(line)
	_v003_hit(lines, i, code, content)
	not _v003_excluded(code)
}
