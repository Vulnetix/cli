# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_772

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-772",
	"name": "Missing Release of Resource after Effective Lifetime",
	"description": "Reports a Java method that acquires an operating-system resource into a local variable and never releases it: a Socket, DatagramSocket, ServerSocket, FileInputStream, FileOutputStream, FileReader, FileWriter, RandomAccessFile, ZipFile or JarFile; a reader, writer, Scanner or object stream constructed directly around a new File stream; a JDBC Connection from DriverManager or a DataSource (including getDataSource().getConnection()); or a stream from Files.lines/list/walk/find/newInputStream/newOutputStream/newBufferedReader/newBufferedWriter. A declaration broken after `=` is read with its next line. It is reported when the declaration is not in a try-with-resources header and the rest of the method has no close() of the variable, no closeQuietly/close helper call with it, no return of it, no assignment of it elsewhere and no hand-off as a call argument. Also reported: a file stream created inline and passed straight to a consumer that does not close it (`props.load(new FileInputStream(p))`, `new Scanner(new File(p)).next()`). Each leaked descriptor or connection stays open until garbage collection, if ever. Not reported: try-with-resources (single- or multi-line headers), close in finally, resources returned to the caller, stored in a field or handed to another object, a ServerSocket serving an accept() loop, in-memory streams (ByteArrayInputStream, StringReader, Scanner(System.in)), comments, string literals and test sources.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-772/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [772],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["resource-release", "cwe-772"],
}

_file_stream := `(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)`

_acquire := concat("", [
	`(?:new\s+(?:Socket|DatagramSocket|ServerSocket|ZipFile|JarFile|`, _file_stream, `)\s*\(`,
	`|new\s+(?:BufferedReader|BufferedWriter|InputStreamReader|OutputStreamWriter|PrintWriter|PrintStream|Scanner|ObjectInputStream|ObjectOutputStream|DataInputStream|DataOutputStream|BufferedInputStream|BufferedOutputStream)\s*\(\s*new\s+(?:File|`, _file_stream, `)\s*\(`,
	`|DriverManager\.getConnection\s*\(|\b(?:[\w.]+\.)?(?:\w*[dD]ataSource|ds|\w*[pP]ool)\.getConnection\s*\(|(?:[\w.]+\.)?get[dD]ataSource\(\s*\)\.getConnection\s*\(`,
	`|Files\.(?:lines|list|walk|find|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|newByteChannel)\s*\()`,
])

# Type var = <acquire>
_decl_re := concat("", [`^\s*(?:final\s+)?[\w.]+(?:<[^=()]*>)?\s+([a-zA-Z_]\w*)\s*=\s*`, _acquire])

# A file stream created inline and consumed without being closed.
_inline_re := concat("", [
	`\.(?:load|loadFromXML|parse|read|readAllBytes|readObject|transferTo|store|storeToXML)\s*\(\s*new\s+`, _file_stream, `\s*\(`,
	`|new\s+(?:Scanner|BufferedReader|ObjectInputStream|InputStreamReader|DataInputStream)\s*\(\s*new\s+(?:File|`, _file_stream, `)\s*\([^;]*\)\s*\)\s*\.\w+\s*\(`,
])

_method_re := `^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default)\s+)*(?:<[^>]*>\s*)?[\w.]+(?:<[^()]*>)?(?:\[\])*\s+\w+\s*\([^;]*$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# Inside a try-with-resources header: this line opens it, or a `try (` above
# is still open (no `{` since).
_in_twr(_, i, line) if regex.match(`\btry\s*\(`, line)

_in_twr(lines, i, _) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`\btry\s*\(`, lines[k])
	not _brace_between(lines, k, i)
}

_brace_between(lines, k, i) if {
	some m in numbers.range(k, i - 1)
	contains(lines[m], "{")
}

# Last line of the enclosing method: the first line after i whose indent is
# at most the method declaration's and that closes a block.
_method_end(lines, i) := e if {
	limit := min([count(lines) - 1, i + 150])
	starts := [k |
		some k in numbers.range(max([0, i - 150]), i)
		regex.match(_method_re, lines[k])
		_indent(lines[k]) < _indent(lines[i])
	]
	ind := _start_indent(lines, starts)
	ends := [k |
		some k in numbers.range(i + 1, limit)
		_indent(lines[k]) <= ind
		startswith(trim_space(lines[k]), "}")
	]
	e := min(array.concat([limit], ends))
}

_start_indent(lines, starts) := _indent(lines[max(starts)]) if count(starts) > 0

_start_indent(_, starts) := 0 if count(starts) == 0

_released(l, v) if regex.match(concat("", [`\b`, v, `\s*\.\s*close\s*\(`]), l)

_released(l, v) if regex.match(concat("", [`[(,]\s*`, v, `\s*[,)]`]), l)

_released(l, v) if regex.match(concat("", [`\breturn\s+`, v, `\s*;`]), l)

_released(l, v) if regex.match(concat("", [`=\s*`, v, `\s*;`]), l)

_released(l, v) if regex.match(concat("", [`\b`, v, `\s*\.\s*accept\s*\(`]), l)

_released_in(lines, a, b, v) if {
	some k in numbers.range(a, b)
	not helpers.is_comment_line(lines[k])
	_released(_strip_strings(lines[k]), v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_acquire, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "=")
	not helpers.is_comment_line(raw)
	line := _joined(lines, i, _strip_strings(raw))
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(m) > 0
	not _in_twr(lines, i, line)
	v := m[0][1]
	e := _method_end(lines, i)
	not _released_in(lines, i + 1, e, v)
	finding := _finding(path, i, raw, sprintf("'%s' holds an OS resource that this method never closes; declare it in try-with-resources", [v]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_inline_re, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "new ")
	not helpers.is_comment_line(raw)
	line := _strip_strings(raw)
	regex.match(_inline_re, line)
	not _in_twr(lines, i, line)
	finding := _finding(path, i, raw, "A file stream is created inline and never closed by the consumer; open it in try-with-resources and pass the variable")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# A declaration broken after `=` continues on the next line.
_joined(lines, i, line) := concat(" ", [line, trim_space(lines[i + 1])]) if {
	endswith(trim_space(line), "=")
	i + 1 < count(lines)
}

_joined(lines, i, line) := line if not _breaks_after_eq(lines, i, line)

_breaks_after_eq(lines, i, line) if {
	endswith(trim_space(line), "=")
	i + 1 < count(lines)
}
