package vulnetix.rules.vnx_tf_002

import rego.v1

metadata := {
	"id": "VNX-TF-002",
	"name": "Terraform AWS security group with unrestricted ingress (0.0.0.0/0)",
	"description": "An AWS security group admits traffic from any address: 0.0.0.0/0 or ::/0 in cidr_blocks or ipv6_cidr_blocks (on one line or in a list spread over several) of an ingress block inside aws_security_group, of an aws_security_group_rule whose type is ingress, or in cidr_ipv4/cidr_ipv6 of an aws_vpc_security_group_ingress_rule; the attribute form ingress = [{ ... }]; and the terraform-aws-modules security-group module's ingress_cidr_blocks (when ingress_rules or the //modules/<preset> names anything but http-80-tcp/https-443-tcp) and the cidr_blocks string of its ingress_with_cidr_blocks objects. Not reported: egress blocks and egress rules, routes and network ACL rules, restricted or variable CIDRs, security-group-to-security-group rules, ingress limited to exactly port 80 or exactly port 443 (a public web listener is open to the world by design; any other port, a port range or all protocols is reported), and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-002/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1220],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["security-group", "network", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

_is_comment(line) if regex.match(`^\s*(#|//|/\*|\*)`, line)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_any_re := `"(0\.0\.0\.0/0|::/0)"`

# A CIDR list that opens on line i and names any address, on that line or on
# the continuation lines up to the closing bracket.
_open_cidr(lines, i) if {
	regex.match(`^\s*(ingress_)?(cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*"(0\.0\.0\.0/0|::/0)"`, lines[i])
}

_open_cidr(lines, i) if {
	regex.match(`^\s*(ingress_)?(cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*$`, lines[i])
	ends := [j | some j in numbers.range(i + 1, min([count(lines) - 1, i + 12])); contains(lines[j], "]")]
	count(ends) > 0
	some j in numbers.range(i + 1, min(ends))
	not _is_comment(lines[j])
	regex.match(_any_re, lines[j])
}

_open_cidr(lines, i) if regex.match(`^\s*cidr_ipv(4|6)\s*=\s*"(0\.0\.0\.0/0|::/0)"`, lines[i])

# The security-group module's ingress_with_cidr_blocks objects take a
# comma-separated string.
_open_cidr(lines, i) if regex.match(`^\s*(cidr_blocks|ipv6_cidr_blocks)\s*=\s*"[^"]*(0\.0\.0\.0/0|::/0)`, lines[i])

# The nearest non-blank line above k that is less indented: the attribute
# that opens the list an object element belongs to.
_opener(lines, k) := max(js) if {
	ind := _indent(lines[k])
	js := [j |
		some j in numbers.range(max([0, k - 60]), k - 1)
		trim_space(lines[j]) != ""
		not _is_comment(lines[j])
		_indent(lines[j]) < ind
	]
	count(js) > 0
}

# The nearest block header that encloses line i.
_header(lines, i) := max(ks) if {
	ind := _indent(lines[i])
	ks := [k |
		some k in numbers.range(max([0, i - 80]), i - 1)
		regex.match(`\{\s*$`, lines[k])
		_indent(lines[k]) < ind
		not _is_comment(lines[k])
	]
	count(ks) > 0
}

_block_end(lines, k) := min(array.concat([min([count(lines) - 1, k + 80])], [j |
	some j in numbers.range(k + 1, min([count(lines) - 1, k + 80]))
	regex.match(`^\s*\}`, lines[j])
	_indent(lines[j]) == _indent(lines[k])
]))

_ingress_block(lines, k) if regex.match(`^\s+ingress\s*\{`, lines[k])

_ingress_block(lines, k) if regex.match(`^resource\s+"aws_vpc_security_group_ingress_rule"`, lines[k])

# Attribute syntax: ingress = [{ ... }], and the security-group module's
# ingress_with_cidr_blocks / ingress_with_ipv6_cidr_blocks objects.
_ingress_block(lines, k) if regex.match(`^\s*ingress\s*=\s*\[\s*\{\s*$`, lines[k])

_ingress_block(lines, k) if {
	regex.match(`^\s*(\}\s*,\s*)?\{\s*$`, lines[k])
	j := _opener(lines, k)
	regex.match(`^\s*(ingress|ingress_with_cidr_blocks|ingress_with_ipv6_cidr_blocks)\s*=\s*\[\s*$`, lines[j])
}

_ingress_block(lines, k) if {
	regex.match(`^resource\s+"aws_security_group_rule"`, lines[k])
	some j in numbers.range(k + 1, _block_end(lines, k))
	regex.match(`^\s*type\s*=\s*"ingress"`, lines[j])
}

_port(lines, k, attr) := to_number(m[0][1]) if {
	vals := [m |
		some j in numbers.range(k + 1, _block_end(lines, k))
		m := regex.find_all_string_submatch_n(sprintf(`^\s*%s\s*=\s*"?(\d+)"?\s*$`, [attr]), lines[j], 1)
		count(m) > 0
	]
	m := vals[0]
}

# Exactly port 80 or exactly port 443: a public web listener.
_web_only(lines, k) if {
	f := _port(lines, k, "from_port")
	f == _port(lines, k, "to_port")
	f in {80, 443}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	regex.match(`(?m)^\s*(cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6)\s*=`, content)
	contains(content, "/0")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6)\s*=`, line)
	_open_cidr(lines, i)
	k := _header(lines, i)
	_ingress_block(lines, k)
	not _web_only(lines, k)
	finding := {
		"rule_id": metadata.id,
		"message": "Security group ingress allows traffic from any address (0.0.0.0/0 or ::/0); restrict the source to the CIDR ranges or security groups that legitimately need this port, or put the service behind a load balancer or VPN",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# terraform-aws-modules/security-group: ingress_cidr_blocks applies to every
# named rule in ingress_rules (or to the preset a //modules/<name> submodule
# opens), so it is reported unless every one of them is a web listener.
_web_rules := {"http-80-tcp", "https-443-tcp"}

_sg_module(lines, k) if {
	regex.match(`^module\s+"`, lines[k])
	some j in numbers.range(k + 1, _block_end(lines, k))
	regex.match(`^\s*source\s*=\s*"[^"]*security-group`, lines[j])
}

_module_non_web(lines, k) if {
	some j in numbers.range(k + 1, _block_end(lines, k))
	m := regex.find_all_string_submatch_n(`^\s*ingress_rules\s*=\s*\[([^\]]*)\]`, lines[j], 1)
	count(m) > 0
	some r in regex.find_all_string_submatch_n(`"([^"]+)"`, m[0][1], -1)
	not _web_rules[r[1]]
}

_module_non_web(lines, k) if {
	some j in numbers.range(k + 1, _block_end(lines, k))
	m := regex.find_all_string_submatch_n(`^\s*source\s*=\s*"[^"]*security-group[^"]*//modules/([A-Za-z0-9_-]+)`, lines[j], 1)
	count(m) > 0
	not m[0][1] in {"http-80", "https-443"}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	contains(content, "security-group")
	regex.match(`(?m)^\s*ingress_(ipv6_)?cidr_blocks\s*=`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*ingress_(ipv6_)?cidr_blocks\s*=`, line)
	_open_cidr(lines, i)
	k := _header(lines, i)
	_sg_module(lines, k)
	_module_non_web(lines, k)
	finding := {
		"rule_id": metadata.id,
		"message": "Security group module opens its ingress rules to any address (0.0.0.0/0 or ::/0); restrict ingress_cidr_blocks to the ranges that legitimately need these ports",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
