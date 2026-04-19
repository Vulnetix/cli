# SPDX-License-Identifier: Apache-2.0
# Cryptographic - MD5 usage detected

package vulnetix.rules.vnx_crypto_001

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-001",
	"name": "MD5 usage detected",
	"description": "MD5 is a broken hash function. Collisions can be generated cheaply, making it unsuitable for integrity checks, signatures, or password hashing.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-001/",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["weak-crypto", "md5", "hash"],
}

_skip(path) if helpers._should_skip(path)

_md5_indicators := {
  "hashlib.md5",
  "MD5.new",
  "Digest::MD5",
  "md5.New(",
  "md5.Sum(",
  "createHash('md5')",
  "createHash(\"md5\")",
  "MessageDigest.getInstance(\"MD5\")",
  "md5(",
}

findings contains finding if {
  some path in object.keys(helpers.input.file_contents)
  not _skip(path)
  lines := split(helpers.input.file_contents[path], "\n")
  some i, line in lines
  some indicator in _md5_indicators
  contains(line, indicator)
  not regex.match(`^\s*(//|/\*)`, line)
  finding := helpers.generate_finding(
    "medium", "warning", metadata.id,
    sprintf("MD5 usage detected (%s); use SHA-256 or stronger", [indicator]),
    helpers.input.artifact_uri,
    i + 1,
    line,
  )
}