package vulnetix.rules.vnx_tf_003

import rego.v1

metadata := {
	"id": "VNX-TF-003",
	"name": "Terraform AWS RDS instance publicly accessible",
	"description": "A managed database instance is given a public endpoint: publicly_accessible = true (or \"true\") anywhere inside an aws_db_instance, aws_rds_cluster_instance, aws_redshift_cluster, aws_redshiftserverless_workgroup or aws_dms_replication_instance resource, or a database module whose source names rds, redshift or dms as a word (so a source path such as ./modules/cards does not count). Not reported: publicly_accessible = false, a value taken from a variable (unknown statically, even when the variable defaults to true), the attribute on other resource types (MQ brokers, Neptune), and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-003/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1220],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["rds", "database", "public-access", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

_db_types := {"aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_dms_replication_instance", "aws_redshiftserverless_workgroup"}

_public_re := `^\s*publicly_accessible\s*=\s*"?true"?\s*(#.*|//.*)?$`

# Index of the column-0 block header enclosing line i (the nearest one above).
_top(lines, i) := max(ks) if {
	ks := [k | some k in numbers.range(max([0, i - 400]), i); regex.match(`^[A-Za-z]`, lines[k])]
	count(ks) > 0
}

_top_end(lines, s) := min(array.concat([count(lines) - 1], [k |
	some k in numbers.range(s + 1, min([count(lines) - 1, s + 600]))
	startswith(lines[k], "}")
]))

_db_block(lines, s) if {
	m := regex.find_all_string_submatch_n(`^resource\s+"([A-Za-z0-9_]+)"`, lines[s], 1)
	_db_types[m[0][1]]
}

_db_block(lines, s) if {
	regex.match(`^module\s+"`, lines[s])
	some k in numbers.range(s + 1, _top_end(lines, s))
	regex.match(`^\s*source\s*=\s*"([^"]*[^A-Za-z"])?(rds|redshift|dms)`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	regex.match(`(?m)^\s*publicly_accessible\s*=\s*"?true`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_public_re, line)
	s := _top(lines, i)
	_db_block(lines, s)
	finding := {
		"rule_id": metadata.id,
		"message": "Database instance has publicly_accessible = true; set it to false, place the instance in private subnets and reach it through the application tier, a bastion or a VPN",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
