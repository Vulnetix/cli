# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1037

import rego.v1

metadata := {
	"id": "VNX-1037",
	"name": "Processor Optimization Removal of Security-critical Code",
	"description": "A compiler or runtime optimizer may eliminate or reorder security-critical code (such as memory zeroing operations) if it determines the result is not used. The classic example is using memset() to clear sensitive data before freeing memory: the compiler can remove the call as a dead-store optimization. Use volatile pointers, explicit_bzero(), or SecureZeroMemory() to prevent this.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1037/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1037],
	"capec": ["CAPEC-188"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["optimization", "memset", "volatile", "dead-store", "memory-zeroing", "cwe-1037"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# memset on security-sensitive variables (may be optimized away)
_memset_patterns := {
	"memset(",
	"bzero(",
	"ZeroMemory(",
	"RtlZeroMemory(",
}

# Patterns that indicate the memory being cleared is security-sensitive
_sensitive_var_names := {
	"password",
	"passwd",
	"secret",
	"key",
	"token",
	"seed",
	"nonce",
	"iv",
	"salt",
	"hash",
	"digest",
	"private",
	"priv_key",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_c_file(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _memset_patterns
	contains(line, p)
	some v in _sensitive_var_names
	contains(line, v)
	not contains(line, "explicit_bzero")
	not contains(line, "SecureZeroMemory")
	not contains(line, "memset_s")
	not contains(line, "volatile")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security-sensitive memory zeroing with '%s' on '%s' may be eliminated by compiler dead-store optimization; use explicit_bzero(), SecureZeroMemory(), or memset_s() which are guaranteed not to be optimized away", [p, v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Detect free() immediately after memset without volatile (possible optimization bypass)
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_c_file(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _memset_patterns
	contains(line, p)
	some j
	j == i + 1
	j < count(lines)
	contains(lines[j], "free(")
	not contains(line, "explicit_bzero")
	not contains(line, "SecureZeroMemory")
	not startswith(trim_space(line), "//")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' immediately followed by free(); the compiler may remove the zeroing call as a dead store. Use explicit_bzero() or SecureZeroMemory() before freeing to ensure sensitive data is cleared", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_c_file(path) if endswith(path, ".c")
_is_c_file(path) if endswith(path, ".cc")
_is_c_file(path) if endswith(path, ".cpp")
_is_c_file(path) if endswith(path, ".h")
_is_c_file(path) if endswith(path, ".hpp")
