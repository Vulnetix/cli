package vulnetix.rules.vnx_tf_001

import rego.v1

metadata := {
	"id": "VNX-TF-001",
	"name": "Terraform AWS S3 bucket with public ACL",
	"description": "An AWS S3 bucket is configured with a public-read or public-read-write ACL, making its contents accessible to the entire internet. Sensitive data stored in the bucket may be exfiltrated.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-001/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [200],
	"capec": ["CAPEC-150"],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["s3", "public-access", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`acl\s*=\s*"public-(read|read-write)"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "S3 bucket ACL set to public-read or public-read-write; remove the public ACL and use aws_s3_bucket_public_access_block to block all public access",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
