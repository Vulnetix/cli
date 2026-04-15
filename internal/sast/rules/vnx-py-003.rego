package vulnetix.rules.vnx_py_003

import rego.v1

metadata := {
	"id": "VNX-PY-003",
	"name": "Insecure deserialization with pickle",
	"description": "pickle.load() and pickle.loads() deserialize arbitrary Python objects. Malicious pickle data can execute arbitrary code during deserialization.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-PY-003",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["deserialization", "dangerous-function"],
}

_is_py(path) if endswith(path, ".py")

_pickle_calls := ["pickle.load(", "pickle.loads(", "cPickle.load(", "cPickle.loads("]

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some call in _pickle_calls
	contains(line, call)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s deserializes arbitrary objects; use json or a safe format instead", [call]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
