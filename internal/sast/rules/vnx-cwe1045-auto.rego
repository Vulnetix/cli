# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1045

import rego.v1

metadata := {
	"id": "VNX-1045",
	"name": "Parent Class with Virtual Destructor and Child Without Virtual Destructor",
	"description": "In C++, if a base class has a virtual destructor but a derived class does not declare one, or if a base class destructor is not virtual but derived classes add resources, deleting a derived object through a base pointer results in undefined behaviour. Only the base destructor is called, causing resource leaks or double-free vulnerabilities.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1045/",
	"languages": ["cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1045],
	"capec": ["CAPEC-123"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["cpp", "virtual-destructor", "memory-safety", "inheritance", "cwe-1045"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Base class destructor not virtual
_non_virtual_destructor_patterns := {
	"~",
}

# Class that inherits from another (public inheritance)
_inheritance_patterns := {
	": public ",
	": protected ",
	": private ",
	":public ",
	":protected ",
	":private ",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_cpp_file(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Class that inherits from another
	some p in _inheritance_patterns
	contains(line, p)
	contains(line, "class ")
	# Check within the next 30 lines for a destructor without virtual
	some j
	j > i
	j <= i + 30
	j < count(lines)
	contains(lines[j], "~")
	contains(lines[j], "()")
	not contains(lines[j], "virtual")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Derived class '%s' has a destructor that is not declared virtual; when deleting via a base class pointer, only the base destructor will be called causing resource leaks. Declare the destructor virtual", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Detect base class with non-virtual destructor when it has virtual methods (indicates polymorphic use)
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	_is_cpp_file(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "class ")
	not contains(line, "final")
	# Has virtual methods
	some j
	j > i
	j <= i + 40
	j < count(lines)
	contains(lines[j], "virtual ")
	not contains(lines[j], "~")
	# But destructor is not virtual
	some k
	k > i
	k <= i + 40
	k < count(lines)
	contains(lines[k], "~")
	not contains(lines[k], "virtual")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": "C++ class with virtual methods has a non-virtual destructor; if this class is used polymorphically (deleted via base pointer), declare the destructor virtual to ensure correct cleanup",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_is_cpp_file(path) if endswith(path, ".cpp")
_is_cpp_file(path) if endswith(path, ".cc")
_is_cpp_file(path) if endswith(path, ".cxx")
_is_cpp_file(path) if endswith(path, ".hpp")
_is_cpp_file(path) if endswith(path, ".hxx")
_is_cpp_file(path) if endswith(path, ".h")
