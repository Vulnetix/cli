# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_704

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-704",
	"name": "File or content size narrowed from long with an unchecked cast",
	"description": "A size or offset that Java reports as a long (the length of a file, an upload or a response body) is cast to int, short, char or byte, so a value past the narrow type's range silently wraps: a 2 GB+ file allocates a negative or tiny buffer (NegativeArraySizeException or a truncated read), and a size checked after the cast passes a limit it exceeds. Reported in .java files: (int)/(short)/(char)/(byte) applied directly to File.length() (a receiver declared File or RandomAccessFile in the file, a receiver named for a file, or new File(...)), Files.size(...), FileChannel.size() (a receiver declared FileChannel/SeekableByteChannel or named channel/fc/...Channel), RandomAccessFile.getFilePointer(), URLConnection.getContentLengthLong(), contentLength(), Apache HttpEntity.getContentLength() (receiver declared HttpEntity), MultipartFile/Part/ZipEntry getSize() and ZipEntry.getCompressedSize(); and such a cast of a variable declared long and assigned from one of those in the 15 lines above. Not reported: Math.toIntExact(...), a variable bounds-checked (compared with Integer.MAX_VALUE or any limit) between the assignment and the cast, casts of parenthesised arithmetic, casts of int-valued calls (String.length(), List.size(), HttpServletRequest.getContentLength(), stream count(), Math.round), including when an int is first widened into a long variable, comments and string literals. Integer.parseInt/Long.parseLong narrowing is VNX-192.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-704/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [704],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incorrect-type-conversion", "narrowing-cast", "cwe-704"],
}

_args := `\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_cast := `\(\s*(?:int|short|char|byte)\s*\)\s*`

# Calls that return a long size or offset.
_long_call := concat("", [
	`(?:\bFiles\s*\.\s*size\s*`, _args,
	`|\bnew\s+File\s*`, _args, `\s*\.\s*length\s*\(\s*\)`,
	`|\b(?:file|raf|[a-z]\w*(?:File|Raf))\s*\.\s*length\s*\(\s*\)`,
	`|\b(?:channel|fc|[a-z]\w*Channel)\s*\.\s*size\s*\(\s*\)`,
	`|[\w.\]()]*\.\s*(?:getFilePointer|getContentLengthLong|contentLength|getSize|getCompressedSize)\s*\(\s*\))`,
])

_inline := concat("", [_cast, _long_call])

# `long size = <expr>;` whose expression is a long size call.
_decl := `^\s*(?:final\s+)?long\s+([A-Za-z_]\w*)\s*=\s*(.*)$`

_long_src := _long_call

# x.length() / x.size() / x.getContentLength() is a long only for these
# receiver types; on a String, a collection or a servlet request it is an int.
_typed(content, recv, "length") if regex.match(concat("", [`\b(?:File|RandomAccessFile)\s+`, recv, `\b`]), content)

_typed(content, recv, "size") if regex.match(concat("", [`\b(?:FileChannel|SeekableByteChannel|AsynchronousFileChannel)\s+`, recv, `\b`]), content)

_typed(content, recv, "getContentLength") if regex.match(concat("", [`\bHttpEntity\s+`, recv, `\b`]), content)

_long_rhs(rhs, _) if regex.match(_long_src, rhs)

_long_rhs(rhs, content) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*\.\s*(length|size|getContentLength)\s*\(\s*\)\s*;`, rhs, 1)
	count(m) > 0
	_typed(content, m[0][1], m[0][2])
}

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_msg := "A long file or content size is narrowed by a cast and silently wraps past the target type's range; use Math.toIntExact() or reject sizes above the limit first"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\(\s*(?:int|short|char|byte)\s*\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\(\s*(?:int|short|char|byte)\s*\)`, line)
	not helpers.is_comment_line(line)
	regex.match(_inline, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\(\s*(?:int|short|char|byte)\s*\)`, content)
	regex.match(`(?m)^\s*(?:final\s+)?long\s+\w+\s*=`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "long")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_decl, line, 1)
	count(m) > 0
	_long_rhs(_code(m[0][2]), content)
	v := m[0][1]
	cast_re := concat("", [_cast, v, `\b`])
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
	not helpers.is_comment_line(lines[j])
	regex.match(cast_re, _code(lines[j]))
	not _bounded(lines, i, j, v)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# The variable is compared with a limit, or passed to toIntExact, between the
# assignment and the cast.
_bounded(lines, i, j, v) if {
	some k in numbers.range(i + 1, j)
	not helpers.is_comment_line(lines[k])
	regex.match(concat("", [`\b`, v, `\s*(?:>=?|<=?)\s*[\w.]|[\w.]\s*(?:>=?|<=?)\s*`, v, `\b|Integer\.MAX_VALUE|toIntExact\s*\(\s*`, v, `\b`]), lines[k])
}

# (int) f.length() where f is declared File/RandomAccessFile in this file,
# (int) ch.size() where ch is a FileChannel, (int) e.getContentLength() where
# e is an Apache HttpEntity.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\(\s*(?:int|short|char|byte)\s*\)\s*\w+\s*\.\s*(?:length|size|getContentLength)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.\s*(?:length|size|getContentLength)\s*\(`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	not regex.match(_inline, code)
	some m in regex.find_all_string_submatch_n(concat("", [_cast, `([A-Za-z_]\w*)\s*\.\s*(length|size|getContentLength)\s*\(\s*\)`]), code, -1)
	_typed(content, m[1], m[2])
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
