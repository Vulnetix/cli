# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_252

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-252",
	"name": "Unchecked Return Value",
	"description": "The error from an I/O call is dropped without a trace. In Go, a bare `conn.Write(buf)` or `f.Read(b)` statement silently discards the error and the byte count. An explicit `_ = x.Close()` is not reported: assigning to the blank identifier is the language's way of saying the discard is deliberate, and Close on a read path or after a successful flush has nothing to act on. Writes to in-memory writers (bytes.Buffer, strings.Builder, hashes), which cannot fail, are not reported. In C, an allocation or fopen result that is assigned and never tested is reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-252/",
	"languages": ["c", "cpp", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [252],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["error-handling", "unchecked", "cwe-252"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

_skip(path) if endswith(path, ".min.css")

_skip(path) if endswith(path, ".min.html")

# A bare statement: `recv.Write(...)` or `recv.Read(...)` and nothing else on
# the line, so the results are neither assigned, tested, deferred nor returned.
_bare_call := `^\s*([A-Za-z_][\w\.]*)\.(Write|Read)\(.*\)\s*$`

# Receivers whose Write cannot fail: in-memory buffers and hashes. The file
# declares the receiver as one of them.
_infallible_decl := `(bytes\.Buffer|bytes\.NewBuffer|strings\.Builder|bufio\.NewWriter|sha1\.New|sha256\.New|sha512\.New|md5\.New|fnv\.New|crc32\.New|crc64\.New|adler32\.New|hash\.Hash|tabwriter\.NewWriter|\.Builder\b)`

_infallible(content, recv) if {
	name := regex.replace(recv, `^.*\.`, "")
	regex.match(concat("", [`\b`, name, `\b[^\n]*(:=|=|\s)[^\n]*`, _infallible_decl]), content)
}

# `w.Write` where w is the standard library's response writer: the client has
# gone, and there is nothing to do about it. Reported by other rules if at all.
_response_writer(recv) if regex.match(`^(w|rw|resp|res|rec|recorder|writer)$`, recv)

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".go")
	not helpers.is_test_path(path)
	content := input.file_contents[path]
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_bare_call, line, 1)
	count(m) > 0
	recv := m[0][1]
	method := m[0][2]
	not _infallible(content, recv)
	not _response_writer(recv)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Error and count from .%s() discarded; check the returned error", [method]),
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
	some _ext in {".c", ".cpp"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	contains(line, "=")
	some _pat in {"malloc(", "calloc(", "fopen("}
	contains(line, _pat)
	not contains(line, "if ")
	not contains(line, "!= NULL")
	not contains(line, "== NULL")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s return value assigned but never checked for NULL/failure", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
