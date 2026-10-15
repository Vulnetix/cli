package vulnetix.rules.vnx_tf_005

import rego.v1

metadata := {
	"id": "VNX-TF-005",
	"name": "Terraform AWS EBS volume unencrypted",
	"description": "An EBS volume is created without encryption at rest: encrypted = false (or \"false\") inside an aws_ebs_volume or aws_ebs_snapshot_copy, inside a root_block_device or ebs_block_device of aws_instance, aws_spot_instance_request or aws_launch_configuration, or inside the ebs block of an aws_launch_template; or an aws_ebs_volume that sets neither encrypted nor snapshot_id as its own attribute (EBS volumes default to unencrypted; a commented-out encrypted line or a tag named encrypted does not count). Not reported: encrypted = true, a value taken from a variable, a volume restored from a snapshot (it inherits the snapshot's encryption), any volume in a project that declares aws_ebs_encryption_by_default with enabled = true (AWS then encrypts every new volume), storage_encrypted on databases, EFS file systems, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-005/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [311],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ebs", "encryption", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

_ebs_types := {
	"aws_ebs_volume", "aws_ebs_snapshot_copy", "aws_instance", "aws_spot_instance_request",
	"aws_launch_configuration", "aws_launch_template",
}

# Index of the column-0 block header enclosing line i (the nearest one above).
_top(lines, i) := max(ks) if {
	ks := [k | some k in numbers.range(max([0, i - 400]), i); regex.match(`^[A-Za-z]`, lines[k])]
	count(ks) > 0
}

_top_end(lines, s) := min(array.concat([count(lines) - 1], [k |
	some k in numbers.range(s + 1, min([count(lines) - 1, s + 600]))
	startswith(lines[k], "}")
]))

_ebs_block(lines, s) if {
	m := regex.find_all_string_submatch_n(`^resource\s+"([A-Za-z0-9_]+)"`, lines[s], 1)
	_ebs_types[m[0][1]]
}

# Account-level default encryption anywhere in the project.
_default_encryption if {
	some p, c in input.file_contents
	_is_tf(p)
	contains(c, "aws_ebs_encryption_by_default")
	regex.match(`(?s)resource\s+"aws_ebs_encryption_by_default"\s+"[^"]+"\s*\{[^}]*\benabled\s*=\s*"?true`, c)
}

_message := "EBS volume is not encrypted at rest; set encrypted = true with a customer-managed kms_key_id, or enable aws_ebs_encryption_by_default for the account"

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	regex.match(`(?m)^\s*encrypted\s*=\s*"?false`, content)
	not _default_encryption
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*encrypted\s*=\s*"?false"?\s*(#.*|//.*)?$`, line)
	_ebs_block(lines, _top(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	contains(content, "aws_ebs_volume")
	not _default_encryption
	lines := split(content, "\n")
	some s, line in lines
	regex.match(`^resource\s+"aws_ebs_volume"\s+"[^"]+"\s*\{\s*$`, line)
	e := _top_end(lines, s)
	not _sets_encryption(lines, s, e)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": s + 1,
		"snippet": line,
	}
}

# encrypted or snapshot_id set as an attribute of the volume itself (depth 1),
# not inside a nested block such as tags.
_sets_encryption(lines, s, e) if {
	some k in numbers.range(s + 1, e)
	regex.match(`^\s*(encrypted|snapshot_id)\s*=`, lines[k])
	_depth(lines, s, k) == 1
}

_depth(lines, s, k) := sum([d |
	some j in numbers.range(s, k - 1)
	d := strings.count(lines[j], "{") - strings.count(lines[j], "}")
])
