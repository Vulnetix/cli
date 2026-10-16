# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_928

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-928",
	"name": "Broken or obsolete cipher (DES, 3DES, RC4, RC2, Blowfish) in Kotlin",
	"description": "CWE-928 is the OWASP Top Ten 2013 view; this rule reports its most concrete Kotlin manifestation, a broken or obsolete symmetric cipher (A6 Sensitive Data Exposure). Java is reported by VNX-CRYPTO-004 (Broken or obsolete cipher, CWE-327), which reads the same JCA and Bouncy Castle forms, so a weak cipher in a .java file is one finding rather than two; this rule reads .kt files only. Reported in Kotlin: Cipher, SecretKeyFactory or KeyGenerator .getInstance with DES, DESede/TripleDES/3DES, RC4/ARCFOUR, RC2 or Blowfish (any mode and padding, the argument possibly on the next line) or a password-based scheme built on one (PBEWithMD5AndDES, PBEWithSHA1AndDESede, PBEWithSHAAnd40BitRC4), Bouncy Castle new DESEngine/DESedeEngine/RC4Engine/RC2Engine/BlowfishEngine(), the same algorithm passed through a String constant assigned in the same file, new SecretKeySpec(key, \"DES\"/\"RC4\"/...), and new DESKeySpec/DESedeKeySpec. Not reported: AES, ChaCha20 and RSA transformations, algorithm names in comments, log messages or other string literals not passed to a crypto API, and identifiers that only start with DES (DESCRIPTOR, DESIGN). A constant defined in another file is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-928/",
	"languages": ["kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [928],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["weak-crypto-mobile", "crypto", "cwe-928"],
}

# Java is reported by VNX-CRYPTO-004, which reads the same JCA and Bouncy
# Castle forms (and more of them) as CWE-327, so a weak cipher in a .java file
# is one finding, not two. Kotlin, which that rule does not read, stays here.
_ext(path) if endswith(path, ".kt")

_weak := `"(?i:(?:PBEWith\w*?And)?(?:des|desede|tripledes|3des|rc4|arcfour|rc2|blowfish)|PBEWith\w*?And\d*Bit(?:RC2|RC4)\w*)(/[^"]*)?"`

_factory := `\b(Cipher|SecretKeyFactory|KeyGenerator)\s*\.\s*getInstance\s*\(\s*`

_sink_re := concat("|", [
	concat("", [_factory, _weak]),
	concat("", [`\bSecretKeySpec\s*\([^;]*,\s*`, _weak]),
	`\bDES(ede)?KeySpec\s*\(`,
	`\bnew\s+(DES|DESede|RC4|RC2|Blowfish)Engine\s*\(`,
])

# The call joined with the next line when its argument starts there.
_call_text(line, _) := line if not regex.match(`getInstance\s*\(\s*$`, line)

_call_text(line, next) := concat(" ", [line, trim_space(next)]) if regex.match(`getInstance\s*\(\s*$`, line)

_next(lines, i) := lines[i + 1] if i + 1 < count(lines)

_next(lines, i) := "" if i + 1 >= count(lines)

# String constants in this file whose value is a weak transformation.
_weak_consts(lines) := {m[0][1] |
	some l in lines
	contains(l, "\"")
	m := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*(:\s*String\s*)?=\s*`, _weak]), l, 1)
	count(m) > 0
}

_hit(line, _) if regex.match(_sink_re, line)

_hit(line, consts) if {
	count(consts) > 0
	m := regex.find_all_string_submatch_n(concat("", [_factory, `([A-Za-z_][\w.]*)\s*[,)]`]), line, 1)
	count(m) > 0
	parts := split(m[0][2], ".")
	parts[count(parts) - 1] in consts
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	regex.match(`getInstance|KeySpec|Engine`, content)
	regex.match(`(?i)"(des|desede|tripledes|3des|rc4|arcfour|rc2|blowfish)[/"]|"PBEWith\w*(DES|RC2|RC4)|DES(ede)?KeySpec\s*\(|(DES|DESede|RC4|RC2|Blowfish)Engine\s*\(`, content)
	lines := split(content, "\n")
	consts := _weak_consts(lines)
	some i, line in lines
	regex.match(`getInstance|KeySpec|Engine`, line)
	not helpers.is_comment_line(line)
	_hit(_call_text(line, _next(lines, i)), consts)
	finding := {
		"rule_id": metadata.id,
		"message": "Broken or obsolete cipher (DES, 3DES, RC4, RC2 or Blowfish): data encrypted with it can be recovered. Use AES-GCM or ChaCha20-Poly1305",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
