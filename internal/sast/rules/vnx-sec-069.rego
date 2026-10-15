package vulnetix.rules.vnx_sec_069

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-069",
	"name": "age secret key",
	"description": "Reports an age identity (secret key): AGE-SECRET-KEY-1 (X25519) or AGE-SECRET-KEY-PQ-1 (the post-quantum hybrid identity of age 1.3) followed by exactly 58 Bech32 characters, in any file, including key files, .env files, CI variables and SOPS_AGE_KEY settings, and in comments (a key in a comment is still leaked). The key is masked in the snippet. Not reported: age public recipients (age1...), the bare AGE-SECRET-KEY-1 prefix used in checks, plugin identities (AGE-PLUGIN-YUBIKEY-1..., which name a hardware key rather than hold one), keys of the wrong length or alphabet, placeholder runs (AGE-SECRET-KEY-1XXXX...), and generated, vendored and test-suffixed files (*_test.go, *.spec.ts...) and testdata/fixtures directories.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-069/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "age", "encryption", "credentials"],
}

# Classic X25519 identities and the post-quantum hybrid ones age 1.3 writes
# (AGE-SECRET-KEY-PQ-1...); both encode a 32-byte secret, 58 Bech32 characters.
_pattern := `AGE-SECRET-KEY-(?:PQ-)?1([QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})(?:[^A-Za-z0-9]|$)`

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "AGE-SECRET-KEY-")
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "AGE-SECRET-KEY-")
	some m in regex.find_all_string_submatch_n(_pattern, line, -1)
	not secrets.is_placeholder(m[1])
	finding := {
		"rule_id": metadata.id,
		"message": "age secret key found; generate a new identity, re-encrypt every file encrypted to the matching public key and remove the old key from history",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, m[1], "***"),
	}
}
