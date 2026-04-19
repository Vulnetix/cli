# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_22

import rego.v1

metadata := {
	"id": "VNX-22",
	"name": "Path Traversal",
	"description": "User-controlled data is used in file path operations without normalisation or validation. An attacker can supply sequences such as '../' to escape the intended directory and read or write arbitrary files on the server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-22/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["path-traversal", "file-access", "cwe-22"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

# Literal traversal sequences embedded in strings
_traversal_literals := {
	"../",
	"..\\",
	"..%2f",
	"..%5c",
}

# Sink functions that accept a path argument — dangerous when user input flows in
_path_sink_patterns := {
	# Node.js
	"fs.readFile(",
	"fs.writeFile(",
	"fs.readFileSync(",
	"fs.writeFileSync(",
	"fs.createReadStream(",
	"fs.createWriteStream(",
	"path.join(",
	"path.resolve(",
	# Python
	"open(",
	"os.open(",
	"os.path.join(",
	"os.path.abspath(",
	"pathlib.Path(",
	# Java
	"new File(",
	"Paths.get(",
	"new FileInputStream(",
	"new FileOutputStream(",
	"new FileReader(",
	# PHP
	"include(",
	"include_once(",
	"require(",
	"require_once(",
	"file_get_contents(",
	"file_put_contents(",
	"fopen(",
	"readfile(",
	# Ruby
	"File.open(",
	"File.read(",
	"File.write(",
	"IO.read(",
	# Go
	"os.Open(",
	"os.Create(",
	"os.ReadFile(",
	"os.WriteFile(",
	"filepath.Join(",
	"ioutil.ReadFile(",
}

# Flag literal traversal sequences anywhere in source
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some traversal in _traversal_literals
	contains(line, traversal)
	not contains(line, "//")
	not contains(line, "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Path traversal sequence '%s' found in source; never construct file paths from user input without normalisation and allowlist validation", [traversal]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Flag file-access sinks where user-derived variables are visible on the same line
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some sink in _path_sink_patterns
	contains(line, sink)
	# Heuristic: user-input variable names on the same line
	_has_user_input(line)
	not contains(line, "//")
	not contains(line, "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("File path operation '%s' may receive user-controlled input; validate and normalise paths, then confirm they are within the intended base directory", [sink]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_has_user_input(line) if contains(line, "req.query")
_has_user_input(line) if contains(line, "req.body")
_has_user_input(line) if contains(line, "req.params")
_has_user_input(line) if contains(line, "request.GET")
_has_user_input(line) if contains(line, "request.POST")
_has_user_input(line) if contains(line, "request.args")
_has_user_input(line) if contains(line, "request.form")
_has_user_input(line) if contains(line, "$_GET")
_has_user_input(line) if contains(line, "$_POST")
_has_user_input(line) if contains(line, "$_REQUEST")
_has_user_input(line) if contains(line, "params[")
_has_user_input(line) if contains(line, "params.")
_has_user_input(line) if contains(line, "getParameter(")
_has_user_input(line) if contains(line, "r.FormValue(")
_has_user_input(line) if contains(line, "r.URL.Query()")
_has_user_input(line) if contains(line, "userInput")
_has_user_input(line) if contains(line, "user_input")
_has_user_input(line) if contains(line, "fileName")
_has_user_input(line) if contains(line, "file_name")
_has_user_input(line) if contains(line, "filePath")
_has_user_input(line) if contains(line, "file_path")
