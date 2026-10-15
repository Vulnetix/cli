package vulnetix.rules.vnx_tf_006

import rego.v1

metadata := {
	"id": "VNX-TF-006",
	"name": "Terraform AWS EC2 instance metadata service v1 (IMDSv1) enabled",
	"description": "An EC2 instance or launch template leaves the token-less IMDSv1 enabled, so any SSRF in software on the instance can read its IAM role credentials from 169.254.169.254. Reported: http_tokens = \"optional\" in the metadata_options of aws_instance, aws_spot_instance_request, aws_launch_template or aws_launch_configuration, or in the metadata_options map of a terraform-aws-modules ec2-instance or autoscaling module; a metadata_options block of aws_instance, aws_spot_instance_request or aws_launch_template that sets no http_tokens (the default is optional); one of those resources with no metadata_options block at all. Not reported: http_tokens = \"required\", a value taken from a variable, http_endpoint = \"disabled\" in the same block (no metadata service, even beside http_tokens = \"optional\"), an aws_instance that takes its settings from a launch_template block, every instance in a project that declares aws_ec2_instance_metadata_defaults with http_tokens = \"required\", data sources, other modules, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-006/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1552.005"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["imds", "ssrf", "ec2", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Index of the column-0 block header enclosing line i (the nearest one above).
_top(lines, i) := max(ks) if {
	ks := [k | some k in numbers.range(max([0, i - 400]), i); regex.match(`^[A-Za-z]`, lines[k])]
	count(ks) > 0
}

_top_end(lines, s) := min(array.concat([count(lines) - 1], [k |
	some k in numbers.range(s + 1, min([count(lines) - 1, s + 600]))
	startswith(lines[k], "}")
]))

_nested_end(lines, k, e) := min(array.concat([e], [j |
	some j in numbers.range(k + 1, e)
	regex.match(`^\s*\}`, lines[j])
	_indent(lines[j]) <= _indent(lines[k])
]))

_compute_re := `^resource\s+"(aws_instance|aws_launch_template|aws_launch_configuration|aws_spot_instance_request)"\s`

_compute_block(lines, s) if regex.match(_compute_re, lines[s])

# terraform-aws-modules ec2-instance / autoscaling take metadata_options as a map.
_compute_block(lines, s) if {
	regex.match(`^module\s+"`, lines[s])
	some k in numbers.range(s + 1, _top_end(lines, s))
	regex.match(`^\s*source\s*=\s*"[^"]*(ec2-instance|autoscaling)`, lines[k])
}

# http_endpoint = "disabled" in the same metadata_options block as the
# http_tokens line: no metadata service at all.
_endpoint_disabled(lines, s, i) if {
	ind := _indent(lines[i])
	ks := [k |
		some k in numbers.range(max([s, i - 20]), i - 1)
		regex.match(`\{\s*$`, lines[k])
		_indent(lines[k]) < ind
	]
	count(ks) > 0
	k := max(ks)
	some j in numbers.range(k + 1, _nested_end(lines, k, _top_end(lines, s)))
	regex.match(`^\s*http_endpoint\s*=\s*"disabled"`, lines[j])
}

_header_re := `^resource\s+"(aws_instance|aws_launch_template|aws_spot_instance_request)"\s+"[^"]+"\s*\{\s*$`

# Account-wide IMDSv2 enforcement anywhere in the project.
_account_required if {
	some p, c in input.file_contents
	_is_tf(p)
	contains(c, "aws_ec2_instance_metadata_defaults")
	regex.match(`(?s)resource\s+"aws_ec2_instance_metadata_defaults"\s+"[^"]+"\s*\{[^}]*http_tokens\s*=\s*"required"`, c)
}

_message := "Instance metadata service allows IMDSv1 (no session token); add metadata_options { http_tokens = \"required\" } (and http_put_response_hop_limit = 1) to enforce IMDSv2 and block SSRF credential theft"

# Explicit http_tokens = "optional".
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	contains(content, "optional")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*http_tokens\s*=\s*"optional"`, line)
	s := _top(lines, i)
	_compute_block(lines, s)
	not _endpoint_disabled(lines, s, i)
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

# A metadata_options block that sets no http_tokens.
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	contains(content, "metadata_options")
	not _account_required
	lines := split(content, "\n")
	some k, line in lines
	regex.match(`^\s+metadata_options\s*\{`, line)
	s := _top(lines, k)
	regex.match(_header_re, lines[s])
	ke := _nested_end(lines, k, _top_end(lines, s))
	not _sets(lines, k, ke, `^\s*(http_tokens|http_endpoint\s*=\s*"disabled")`)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": line,
	}
}

# No metadata_options block at all.
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	regex.match(`resource\s+"(aws_instance|aws_launch_template|aws_spot_instance_request)"`, content)
	not _account_required
	lines := split(content, "\n")
	some s, line in lines
	regex.match(_header_re, line)
	e := _top_end(lines, s)
	not _sets(lines, s, e, `^\s*(metadata_options|launch_template)\s*\{`)
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

_sets(lines, s, e, re) if {
	some j in numbers.range(s + 1, e)
	regex.match(re, lines[j])
}
