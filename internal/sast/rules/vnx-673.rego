# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_673

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-673",
	"name": "Control sphere (chroot jail, import or library search path) defined by remote input",
	"description": "Python code lets a remote party define the boundary the process trusts: data from an HTTP request (Flask/Django/aiohttp/DRF request.args/form/values/json/data/get_json()/GET/POST/query_params/match_info/params/body/cookies/headers, Tornado self.get_argument) or read from a socket (recv/recvfrom) reaches os.chroot() (the jail root), sys.path.insert()/sys.path.append() or site.addsitedir() (where modules are imported from), or an assignment/os.putenv of PATH (in os.environ or in an environment mapping such as env = os.environ.copy() handed to subprocess), PYTHONPATH, PYTHONHOME, LD_LIBRARY_PATH, LD_PRELOAD or a DYLD_* variable (where programs and shared libraries are loaded from). The source may be on the sink line or assigned to a variable in the 10 lines above. Not reported: constants, settings and other configuration values, paths built from __file__ or BASE_DIR, command-line arguments (sys.argv, argparse: chosen by the operator, not a remote actor), a request value that was first mapped through an allow-list into a different variable, other environment variables, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-673/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [673],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["external-influence-sphere-definition", "cwe-673", "python"],
}

_source_re := `\brequest\.(?:args|form|values|json|data|files|cookies|headers|GET|POST|body|query_params|get_json|params|match_info|query|rel_url)\b|\bself\.get_argument\(|\.recv(?:from)?\(`

_sinks := [
	[`^\s*(?:os\.)?chroot\((.*)$`, "os.chroot() jail root"],
	[`^\s*sys\.path\.insert\(\s*[^,]+,(.*)$`, "sys.path (module import path)"],
	[`^\s*sys\.path\.append\((.*)$`, "sys.path (module import path)"],
	[`^\s*site\.addsitedir\((.*)$`, "site directory (module import path)"],
	[`^\s*(?:os\.environ|[A-Za-z_]\w*(?:\.\w+)*)\s*\[\s*['"](?:PATH|PYTHONPATH|PYTHONHOME|LD_LIBRARY_PATH|LD_PRELOAD|DYLD_\w+)['"]\s*\]\s*=(.*)$`, "program/library search path"],
	[`^\s*os\.putenv\(\s*['"](?:PATH|PYTHONPATH|PYTHONHOME|LD_LIBRARY_PATH|LD_PRELOAD|DYLD_\w+)['"]\s*,(.*)$`, "program/library search path"],
]

_strip(s) := regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

_tainted(_, _, arg) if regex.match(_source_re, arg)

_tainted(lines, i, arg) if {
	some v in helpers.tainted_names(lines, i, 10, _source_re)
	regex.match(concat("", [`(?:^|[^\w.])`, v, `\b`]), _strip(arg))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`chroot\(|sys\.path\.|addsitedir\(|PATH|LD_|DYLD_|PYTHONHOME`, content)
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, line in lines
	some sink in _sinks
	m := regex.find_all_string_submatch_n(sink[0], line, 1)
	arg := m[0][1]
	_tainted(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Remote input defines the %s: an attacker chooses what the process trusts. Map the request to a fixed, allow-listed value instead", [sink[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
