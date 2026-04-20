# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_250

import rego.v1

metadata := {
	"id": "VNX-250",
	"name": "Execution with unnecessary privileges",
	"description": "Running code with elevated privileges (root/SYSTEM/setuid) when not required violates the principle of least privilege. If the process is compromised, an attacker immediately gains the elevated privilege level, dramatically increasing the blast radius of any vulnerability.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-250/",
	"languages": ["c", "cpp", "python", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [250],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1548.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["privilege-escalation", "least-privilege", "setuid", "cwe-250"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_c_privilege_patterns := {
	"setuid(0)",
	"setgid(0)",
	"seteuid(0)",
	"setegid(0)",
	"setreuid(0,",
	"setregid(0,",
	"prctl(PR_SET_SECCOMP",
	"cap_set_proc(",
}

_python_privilege_patterns := {
	"os.setuid(0)",
	"os.setgid(0)",
	"os.seteuid(0)",
	"os.setegid(0)",
	"os.setuid(root",
	"os.getuid() == 0",
	"subprocess.run([\"sudo\"",
	"subprocess.call([\"sudo\"",
}

_go_privilege_patterns := {
	"syscall.Setuid(0)",
	"syscall.Setgid(0)",
	"syscall.Seteuid(0)",
	"unix.Setuid(0)",
	"unix.Setgid(0)",
	"os.Getuid() == 0",
	"os/user",
}

_is_c_file(path) if endswith(path, ".c")
_is_c_file(path) if endswith(path, ".cpp")
_is_c_file(path) if endswith(path, ".cc")
_is_c_file(path) if endswith(path, ".cxx")
_is_c_file(path) if endswith(path, ".h")
_is_c_file(path) if endswith(path, ".hpp")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_c_file(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _c_privilege_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Privilege escalation to root near '%v'; drop privileges to the minimum required UID/GID as early as possible and do not run the full process as root", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _python_privilege_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Elevated privilege usage near '%v'; ensure operations requiring elevated privileges are isolated and the process drops privileges immediately afterwards", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _go_privilege_patterns
	contains(line, pattern)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Privilege-related syscall or root check near '%v'; verify the process runs with least privilege and that any privileged operations are performed in an isolated, short-lived context", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
