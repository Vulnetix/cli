package vulnetix.rules.vnx_crypto_002

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-002",
	"name": "SHA-1 usage detected",
	"description": "SHA-1 is cryptographically broken. Practical collision attacks exist (SHAttered). Use SHA-256 or SHA-3 instead.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-CRYPTO-002",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [328],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-crypto", "sha1", "hash"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

_sha1_indicators := {
	"hashlib.sha1",
	"Digest::SHA1",
	"SHA1.new",
	"sha1.New(",
	"sha1.Sum(",
	"createHash('sha1')",
	"createHash(\"sha1\")",
	"MessageDigest.getInstance(\"SHA-1\")",
	"sha1(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _sha1_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SHA-1 usage detected (%s); use SHA-256 or stronger", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
