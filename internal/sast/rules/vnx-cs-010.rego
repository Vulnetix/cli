package vulnetix.rules.vnx_cs_010

import rego.v1

metadata := {
	"id": "VNX-CS-010",
	"name": "C# hardcoded connection string with credentials",
	"description": "A database connection string containing a password, user ID, or other credentials appears to be hardcoded in source code. Hardcoded credentials can be extracted by anyone with read access to the codebase and cannot be rotated without a code change.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-010/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["hardcoded-credentials", "secrets", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Connection string pattern with Password= or pwd= or User ID=
	regex.match(`(?i)(Password|pwd)\s*=\s*[^;{}\s][^;]*;`, line)
	# On a string literal (not a format template or config read)
	contains(line, "\"")
	not regex.match(`ConfigurationManager|GetConnectionString|Environment\.Get|appsettings`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded database credentials found in connection string; store credentials in environment variables, Azure Key Vault, or .NET Secret Manager and retrieve them at runtime",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
