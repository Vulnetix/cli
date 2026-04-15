package vulnetix.rules.vnx_cs_009

import rego.v1

metadata := {
	"id": "VNX-CS-009",
	"name": "C# use of weak cryptographic algorithm (MD5, SHA1, DES, RC2, 3DES)",
	"description": "MD5, SHA-1, DES, RC2, or TripleDES is used for cryptographic operations. These algorithms are considered weak or broken and should not be used for security-sensitive operations such as password hashing, message authentication, or encryption.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-009/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["weak-crypto", "cryptography", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

_weak_algos := {
	"MD5",
	"SHA1",
	"SHA1Managed",
	"DES",
	"DESCryptoServiceProvider",
	"RC2",
	"RC2CryptoServiceProvider",
	"TripleDES",
	"TripleDESCryptoServiceProvider",
	"MD5CryptoServiceProvider",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some algo in _weak_algos
	contains(line, algo)
	regex.match(`new\s+` + algo + `\s*\(|` + algo + `\.Create\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak cryptographic algorithm %s detected; use SHA-256/SHA-3 for hashing, AES-GCM for encryption, and PBKDF2/bcrypt/Argon2 for password hashing", [algo]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
