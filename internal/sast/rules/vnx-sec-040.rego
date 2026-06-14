package vulnetix.rules.vnx_sec_040

import rego.v1

metadata := {
	"id": "VNX-SEC-040",
	"name": "GitLab pipeline trigger / deploy / runner token",
	"description": "A GitLab pipeline trigger, deploy, runner registration, runner authentication, or Kubernetes agent token was found in source code. These tokens grant automated access to GitLab CI infrastructure.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-040/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "gitlab", "ci", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_gl_tokens := [
	# GitLab pipeline trigger, deploy, runner, agent, CI, OAuth, mail, FF, feed, SCIM, runner registration
	"glptt-",
	"gldt-",
	"glrt-",
	"glagent-",
	"glcbt-",
	"gloas-",
	"glimt-",
	"glffct-",
	"glft-",
	"glsoat-",
	"GR1348941"
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some prefix in _gl_tokens
	contains(line, prefix)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GitLab infrastructure token (%s) found; revoke the token in GitLab admin/pipeline settings", [prefix]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
