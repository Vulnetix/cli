# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_272

import rego.v1

metadata := {
	"id": "VNX-272",
	"name": "Least Privilege Violation",
	"description": "The software does not restrict its privilege level to the minimum required, running as root or gaining elevated privileges unnecessarily. This violates the principle of least privilege and exposes the system to greater risk if the process is compromised.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-272/",
	"languages": ["python", "shell", "go", "c"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [272],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1548"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["privilege", "least-privilege", "root", "setuid", "cwe-272"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Python: explicit privilege escalation to root
_python_root_patterns := {
	"os.setuid(0)",
	"os.setgid(0)",
	"os.seteuid(0)",
	"os.setegid(0)",
	"os.setresuid(0",
	"os.setresgid(0",
}

# Shell: sudo usage patterns that indicate unnecessary privilege escalation
_shell_sudo_patterns := {
	"sudo su",
	"sudo -i",
	"sudo bash",
	"sudo sh",
	"sudo -s",
	"runuser -l root",
}

# C: setuid/setgid to root (0)
_c_root_patterns := {
	"setuid(0)",
	"setgid(0)",
	"seteuid(0)",
	"setegid(0)",
}

# Go: syscall to set UID/GID to 0
_go_root_patterns := {
	"syscall.Setuid(0)",
	"syscall.Setgid(0)",
	"syscall.Seteuid(0)",
	"syscall.Setegid(0)",
}

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _python_root_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Least privilege violation: '%s' sets process UID/GID to root (0). Run the process under a non-privileged user and drop privileges only when absolutely required.", [pattern]),
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
	some _ext in {".sh", ".bash", ".zsh"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _shell_sudo_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Least privilege violation: shell script uses '%s' to obtain a root shell. Scripts should not escalate to root; use targeted sudo rules for specific commands instead.", [pattern]),
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
	some _ext in {".c", ".cpp", ".h"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _c_root_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Least privilege violation: '%s' sets process credentials to root (UID/GID 0). Drop privileges to a dedicated non-root user and only elevate for specific privileged operations.", [pattern]),
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
	some pattern in _go_root_patterns
	contains(line, pattern)
	not _is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Least privilege violation: '%s' sets process credentials to root (0). Use a non-privileged user identity and avoid running as root.", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
