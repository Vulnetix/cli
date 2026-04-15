package vulnetix.rules.vnx_go_018

import rego.v1

metadata := {
	"id": "VNX-GO-018",
	"name": "Go arbitrary file write via os.WriteFile/os.Create with user-controlled path",
	"description": "os.WriteFile(), os.Create(), or os.OpenFile() is called with a path that may be derived from user input without validation. An attacker can supply '../' sequences or absolute paths to write files outside the intended directory, potentially overwriting configuration files or executables.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-018/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["path-traversal", "file-write", "go"],
}

_is_go(path) if endswith(path, ".go")

_write_funcs := {
	"os.WriteFile(",
	"os.Create(",
	"ioutil.WriteFile(",
}

_request_sources := {
	"r.URL",
	"r.FormValue",
	"r.PostFormValue",
	"r.PathValue",
	"mux.Vars(",
	"chi.URLParam(",
	"c.Param(",
	"c.Query(",
	"ctx.Param(",
	"ctx.Query(",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some fn in _write_funcs
	contains(line, fn)
	not regex.match(`^\s*//`, line)
	# Check for user input sources in surrounding context
	window_start := max([0, i - 15])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	some src in _request_sources
	contains(window, src)
	not contains(window, "filepath.Clean")
	not contains(window, "filepath.Rel(")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("File write function %s called with a path derived from user input; validate the path with filepath.Clean() and confirm it starts with the intended base directory before writing", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
