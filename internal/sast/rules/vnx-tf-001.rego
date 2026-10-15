package vulnetix.rules.vnx_tf_001

import rego.v1

metadata := {
	"id": "VNX-TF-001",
	"name": "Terraform S3 bucket or object with a public ACL",
	"description": "An S3 bucket or object is made readable or writable by everyone through its ACL: acl = \"public-read\", \"public-read-write\" or \"authenticated-read\" inside an aws_s3_bucket, aws_s3_bucket_acl, aws_s3_object, aws_s3_bucket_object or alicloud_oss_bucket resource or an S3 bucket module (a module whose source names s3), or a grant/grantee uri naming the AllUsers or AuthenticatedUsers group. Not reported: private, log-delivery-write and other canned ACLs, an ACL taken from a variable (the value is unknown), grants to canonical users or the LogDelivery group, a bucket whose own aws_s3_bucket_public_access_block (in any file of the project) sets block_public_acls or ignore_public_acls = true, an S3 module whose own inputs set either to true, any bucket when an aws_s3_account_public_access_block anywhere in the project does, the attribute in other resource types or modules, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-001/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [200],
	"capec": ["CAPEC-150"],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["s3", "public-access", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

_canned_re := `^\s*acl\s*=\s*"(public-read|public-read-write|authenticated-read)"`

_grant_re := `^\s*uri\s*=\s*"https?://acs\.amazonaws\.com/groups/global/(AllUsers|AuthenticatedUsers)"`

_s3_types := {"aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_object", "aws_s3_bucket_object", "alicloud_oss_bucket"}

# Index of the column-0 block header enclosing line i (the nearest one above).
_top(lines, i) := max(ks) if {
	ks := [k | some k in numbers.range(max([0, i - 400]), i); regex.match(`^[A-Za-z]`, lines[k])]
	count(ks) > 0
}

# The column-0 closing brace of the block opened at s.
_top_end(lines, s) := min(array.concat([count(lines) - 1], [k |
	some k in numbers.range(s + 1, min([count(lines) - 1, s + 600]))
	startswith(lines[k], "}")
]))

_s3_block(lines, s) if {
	m := regex.find_all_string_submatch_n(`^resource\s+"([A-Za-z0-9_]+)"`, lines[s], 1)
	_s3_types[m[0][1]]
}

_s3_block(lines, s) if {
	regex.match(`^module\s+"`, lines[s])
	some k in numbers.range(s + 1, _top_end(lines, s))
	regex.match(`^\s*source\s*=\s*"[^"]*s3`, lines[k])
}

# The aws_s3_bucket resource name a block configures.
_bucket_name(lines, s) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^resource\s+"aws_s3_bucket"\s+"([^"]+)"`, lines[s], 1)
	count(m) > 0
}

_bucket_name(lines, s) := m[0][1] if {
	not regex.match(`^resource\s+"aws_s3_bucket"\s`, lines[s])
	some k in numbers.range(s + 1, _top_end(lines, s))
	m := regex.find_all_string_submatch_n(`^\s*bucket\s*=\s*aws_s3_bucket\.([A-Za-z0-9_-]+)\.`, lines[k], 1)
	count(m) > 0
}

_blocks_acls_re := `(?m)^\s*(block_public_acls|ignore_public_acls)\s*=\s*true`

# Buckets guarded by an aws_s3_bucket_public_access_block anywhere in the
# project whose own block names the bucket and sets block_public_acls or
# ignore_public_acls = true.
_guarded_buckets contains name if {
	some p, c in input.file_contents
	_is_tf(p)
	contains(c, "aws_s3_bucket_public_access_block")
	regex.match(_blocks_acls_re, c)
	lines := split(c, "\n")
	some s, hdr in lines
	regex.match(`^resource\s+"aws_s3_bucket_public_access_block"`, hdr)
	e := _top_end(lines, s)
	some j in numbers.range(s + 1, e)
	regex.match(`^\s*(block_public_acls|ignore_public_acls)\s*=\s*true`, lines[j])
	some k in numbers.range(s + 1, e)
	m := regex.find_all_string_submatch_n(`^\s*bucket\s*=\s*aws_s3_bucket\.([A-Za-z0-9_-]+)\.`, lines[k], 1)
	count(m) > 0
	name := m[0][1]
}

_mitigated(lines, s) if {
	name := _bucket_name(lines, s)
	_guarded_buckets[name]
}

# An S3 module that blocks public ACLs in its own inputs.
_mitigated(lines, s) if {
	regex.match(`^module\s+"`, lines[s])
	some k in numbers.range(s + 1, _top_end(lines, s))
	regex.match(`^\s*(block_public_acls|ignore_public_acls)\s*=\s*true`, lines[k])
}

# An account-level public access block anywhere in the project.
_account_block if {
	some p, c in input.file_contents
	_is_tf(p)
	contains(c, "aws_s3_account_public_access_block")
	regex.match(_blocks_acls_re, c)
}

_public_line(line) if regex.match(_canned_re, line)

_public_line(line) if regex.match(_grant_re, line)

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	regex.match(`(?m)^\s*(acl|uri)\s*=\s*"(public-read|authenticated-read|https?://acs\.amazonaws\.com/groups/global/A)`, content)
	not _account_block
	lines := split(content, "\n")
	some i, line in lines
	_public_line(line)
	s := _top(lines, i)
	_s3_block(lines, s)
	not _mitigated(lines, s)
	finding := {
		"rule_id": metadata.id,
		"message": "S3 ACL grants access to everyone (public-read, public-read-write, authenticated-read or an AllUsers/AuthenticatedUsers grant); use a private ACL, serve public content through CloudFront with origin access control, and enable an S3 public access block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
