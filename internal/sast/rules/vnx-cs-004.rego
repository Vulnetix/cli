package vulnetix.rules.vnx_cs_004

import rego.v1

metadata := {
	"id": "VNX-CS-004",
	"name": "C# insecure deserialization via BinaryFormatter or SoapFormatter",
	"description": "BinaryFormatter, SoapFormatter, NetDataContractSerializer, or LosFormatter deserialise arbitrary .NET object graphs from untrusted input. An attacker can craft a payload that executes arbitrary code during deserialisation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-004/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["deserialization", "csharp"],
}

_is_cs(path) if endswith(path, ".cs")

_dangerous_formatters := {
	"BinaryFormatter",
	"SoapFormatter",
	"NetDataContractSerializer",
	"LosFormatter",
	"ObjectStateFormatter",
	"JavaScriptSerializer",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_cs(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some formatter in _dangerous_formatters
	contains(line, formatter)
	# Only flag instantiation or Deserialize call
	regex.match(sprintf(`new\s+%s|%s\s*\(\s*\)|\.Deserialize\s*\(`, [formatter, formatter]), line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure deserialisation using %s; replace with a safe serialiser (System.Text.Json, XmlSerializer with schema validation) and never deserialise untrusted data with this formatter", [formatter]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
