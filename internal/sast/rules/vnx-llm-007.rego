package vulnetix.rules.vnx_llm_007

import rego.v1

metadata := {
	"id": "VNX-LLM-007",
	"name": "torch.load() without weights_only=True (ML model deserialization)",
	"description": "torch.load() uses Python's pickle internally to deserialize model files. Loading an untrusted or attacker-supplied model file can result in arbitrary code execution. Pass weights_only=True (PyTorch >= 1.13) to restrict deserialization to tensors only, or use the safetensors format for model weights.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-007/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["deserialization", "pytorch", "ml", "ai-security", "python"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`torch\.load\s*\(`, line)
	not contains(line, "weights_only=True")
	finding := {
		"rule_id": metadata.id,
		"message": "torch.load() without weights_only=True can execute arbitrary code when loading untrusted model files; add weights_only=True or migrate to the safetensors format",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
