package vulnetix.rules.vnx_py_013

import rego.v1

metadata := {
	"id": "VNX-PY-013",
	"name": "Python ML/AI insecure deserialization",
	"description": "Loading ML model files with pickle-based deserializers (torch.load, joblib.load, pandas.read_pickle, numpy.load with allow_pickle) can execute arbitrary code embedded in the model file.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-013/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["deserialization", "ml", "pytorch", "pickle", "supply-chain"],
}

_is_py(path) if endswith(path, ".py")

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_ml_deser_indicators := {
	"torch.load(",
	"joblib.load(",
	"pandas.read_pickle(",
	"pd.read_pickle(",
	"pickle.load(",
	"pickle.loads(",
	"cPickle.load(",
	"cPickle.loads(",
	"shelve.open(",
	"dill.load(",
	"dill.loads(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ml_deser_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure deserialization via %s; use safe loading methods (e.g., torch.load with weights_only=True, safetensors)", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`numpy\.load\(.*allow_pickle\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "numpy.load with allow_pickle=True enables arbitrary code execution; use allow_pickle=False or numpy-specific formats",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`np\.load\(.*allow_pickle\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "numpy.load with allow_pickle=True enables arbitrary code execution; use allow_pickle=False or numpy-specific formats",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
