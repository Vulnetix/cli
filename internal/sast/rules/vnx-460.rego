# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_460

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-460",
	"name": "Improper Cleanup on Thrown Exception",
	"description": "Java code whose cleanup runs only on the normal path, so an exception thrown in between skips it. Reported: a Lock acquired with x.lock() (including readLock()/writeLock()) and released by x.unlock() later in the same block with no finally between them, which leaves the lock held forever if the code in between throws; and a closeable resource (FileInputStream/FileOutputStream/FileReader/FileWriter/Buffered*/PrintWriter/RandomAccessFile/Socket/ZipFile/Object*Stream/Scanner, DriverManager or DataSource getConnection(), prepareStatement/createStatement, Files.newInputStream/newBufferedReader...) assigned to a variable that is later closed with v.close() in the same block with no finally between, so the handle leaks on any exception. Not reported: the lock()/try/finally idiom, try-with-resources, close() or unlock() inside a finally block, tryLock() branches, a resource returned to the caller without a close(), a lock released in a different method, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-460/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [460],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["improper-cleanup", "cwe-460"],
}

_lock_re := `^\s*((?:this\.)?[A-Za-z_][\w.]*(?:\(\))?(?:\.(?:readLock|writeLock)\(\))?)\.lock(?:Interruptibly)?\(\)\s*;`

_permit_re := `^\s*((?:this\.)?[A-Za-z_][\w.]*)\.acquire(?:Uninterruptibly)?\(\s*\w*\s*\)\s*;`

_res_ctor := `FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter|BufferedInputStream|BufferedOutputStream|InputStreamReader|OutputStreamWriter|PrintWriter|PrintStream|RandomAccessFile|Socket|ServerSocket|ZipFile|JarFile|ZipInputStream|ZipOutputStream|ObjectInputStream|ObjectOutputStream|DataInputStream|DataOutputStream|Scanner`

_res_re := concat("", [
	`^\s*(?:final\s+)?(?:[A-Za-z_][\w.<>\[\], ]*\s+)?([A-Za-z_]\w*)\s*=\s*(?:new\s+(?:\w+\.)*(?:`, _res_ctor,
	`)\s*\(|(?:DriverManager|\w*[dD]ata[sS]ource|\w*[pP]ool)\.getConnection\s*\(|\w+\.(?:prepareStatement|prepareCall|createStatement)\s*\(|Files\.(?:newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|newByteChannel|lines|list|walk)\s*\(|FileChannel\.open\s*\(|(?:new\s+URL\s*\([^;]*?\)|[A-Za-z_]\w*)\.openStream\s*\(\s*\)|[A-Za-z_]\w*\.accept\s*\(\s*\))`,
])

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

# The receiver acquired or opened on this line, and the release call to look for.
_acquire(l) := [m[0][1], concat("", [m[0][1], ".release("])] if {
	contains(l, ".acquire")
	m := regex.find_all_string_submatch_n(_permit_re, l, 1)
	count(m) > 0
}

_acquire(l) := [m[0][1], concat("", [m[0][1], ".unlock()"])] if {
	contains(l, ".lock")
	m := regex.find_all_string_submatch_n(_lock_re, l, 1)
	count(m) > 0
}

_acquire(l) := [m[0][1], concat("", [m[0][1], ".close()"])] if {
	not startswith(trim_space(l), "try")
	m := regex.find_all_string_submatch_n(_res_re, l, 1)
	count(m) > 0
}

# The release in the same block, after at least one statement, with no
# finally (or block end) in between.
_unprotected(lines, i, s, release) if {
	ind := _indent(lines[i])
	last := min([count(lines) - 1, i + 40])
	last >= s + 2
	js := [k |
		some k in numbers.range(s + 2, last)
		contains(lines[k], release)
		not helpers.is_comment_line(lines[k])
	]
	count(js) > 0
	j := js[0]
	not _guarded(lines, i, j, ind)
}

_guarded(lines, i, j, _) if {
	some k in helpers.span(i + 1, j - 1)
	regex.match(`\bfinally\b`, lines[k])
}

_guarded(lines, i, j, ind) if {
	some k in helpers.span(i + 1, j - 1)
	trim_space(lines[k]) != ""
	_indent(lines[k]) < ind
}

# [statement text, index of its last line]: a declaration ending in `=`
# continues on the next line.
_statement(lines, i) := [lines[i], i] if not regex.match(`=\s*$`, lines[i])

_statement(lines, i) := [concat(" ", [lines[i], trim_space(lines[i + 1])]), i + 1] if {
	regex.match(`=\s*$`, lines[i])
	i + 1 < count(lines)
}

# The standard streams are not the method's to release.
_in_memory(_, line) if regex.match(`\bSystem\.(?:in|out|err)\b`, line)

# A Scanner over a String reads memory.
_in_memory(_, line) if regex.match(`new\s+Scanner\s*\(\s*(?:"|[A-Za-z_]\w*\.(?:nextLine|readLine|trim|toString)\(\))`, line)

_in_memory(content, line) if {
	m := regex.find_all_string_submatch_n(`new\s+Scanner\s*\(\s*([A-Za-z_]\w*)\s*\)`, line, 1)
	count(m) > 0
	regex.match(concat("", [`\bString\s+`, m[0][1], `\b`]), content)
}

# A stream wrapped around an in-memory buffer holds no OS handle.
_in_memory(_, line) if regex.match(`new\s+(?:ByteArray(?:Input|Output)Stream|StringReader|StringWriter|CharArray(?:Reader|Writer))\b`, line)

_in_memory(content, line) if {
	m := regex.find_all_string_submatch_n(`new\s+\w+\s*\(\s*([A-Za-z_]\w*)\s*\)`, line, 1)
	count(m) > 0
	regex.match(concat("", [`\b`, m[0][1], `\s*=\s*new\s+(?:ByteArray(?:Input|Output)Stream|StringReader|StringWriter|CharArray(?:Reader|Writer))\b`]), content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\.unlock\(\)|\.close\(\)|\.release\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.lock|\.acquire|=`, line)
	not helpers.is_comment_line(line)
	st := _statement(lines, i)
	a := _acquire(_strip(st[0]))
	not _in_memory(content, st[0])
	_unprotected(lines, i, st[1], a[1])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is released only on the normal path; an exception before %s skips it. Release it in a finally block or use try-with-resources", [a[0], a[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
