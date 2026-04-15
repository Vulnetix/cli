package vulnetix.rules.vnx_php_021

import rego.v1

metadata := {
	"id": "VNX-PHP-021",
	"name": "Laravel mass assignment via empty guarded array",
	"description": "A Laravel Eloquent model sets $guarded to an empty array ([]), which disables mass-assignment protection entirely. Any attribute can be set via Model::create() or fill() with request data, allowing attackers to set privileged fields such as is_admin, role, or password. Set $fillable to an explicit allowlist of safe attributes instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-021/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [915],
	"capec": ["CAPEC-77"],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["mass-assignment", "laravel", "eloquent", "php"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\$guarded\s*=\s*\[\s*\]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "$guarded = [] disables all mass-assignment protection in this Laravel model; define $fillable with only the attributes that should be mass-assignable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "Model::unguard()")
	finding := {
		"rule_id": metadata.id,
		"message": "Model::unguard() disables mass-assignment protection globally; remove this call and define $fillable on each model instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
