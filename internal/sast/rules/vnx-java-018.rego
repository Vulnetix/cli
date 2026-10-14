package vulnetix.rules.vnx_java_018

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-018",
	"name": "Java RSA cipher without OAEP padding",
	"description": "An RSA javax.crypto.Cipher is created with PKCS#1 v1.5 padding or no padding, which leaves decryption open to Bleichenbacher-style padding-oracle attacks (and raw RSA is deterministic and malleable). Reported: Cipher.getInstance() whose transformation is the literal \"RSA\" (which SunJCE resolves to RSA/ECB/PKCS1Padding), RSA/<mode>/PKCS1Padding or RSA/<mode>/NoPadding in any letter case, with or without a provider argument, written inline, on the following line, or through a String constant or variable assigned such a literal in the same file. Not reported: OAEP transformations, other algorithms (AES/GCM/NoPadding), Signature, KeyPairGenerator and KeyFactory instances for RSA, a transformation passed in as a parameter, and the text in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-018/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [780],
	"capec": ["CAPEC-463"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "rsa", "padding", "java"],
}

_weak_literal := `^(?i:"RSA(/[^/"]*/(PKCS1Padding|NoPadding))?")$`

_strip_strings(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

# String constants or variables in this file holding a weak RSA transformation.
_weak_names(lines) := {m[1] |
	some l in lines
	contains(lower(l), "\"rsa")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?i:"RSA(?:/[^/"]*/(?:PKCS1Padding|NoPadding))?")\s*;`, l, -1)
}

# The first argument of the getInstance call that starts on line i, read
# across at most two following lines.
_first_arg(lines, i) := a if {
	end := min([count(lines) - 1, i + 2])
	txt := concat(" ", [regex.replace(lines[k], `//.*$`, "") | some k in numbers.range(i, end)])
	m := regex.find_all_string_submatch_n(`Cipher\s*\.\s*getInstance\s*\(\s*([^),]*)`, txt, 1)
	count(m) > 0
	a := trim_space(m[0][1])
}

_weak(_, arg) if regex.match(_weak_literal, arg)

_weak(lines, arg) if arg in _weak_names(lines)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "getInstance")
	regex.match(`(?i)"RSA`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "getInstance")
	not helpers.is_comment_line(line)
	regex.match(`Cipher\s*\.\s*getInstance\s*\(`, _strip_strings(line))
	arg := _first_arg(lines, i)
	_weak(lines, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "RSA cipher uses PKCS#1 v1.5 or no padding; use RSA/ECB/OAEPWithSHA-256AndMGF1Padding to prevent padding oracle attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
