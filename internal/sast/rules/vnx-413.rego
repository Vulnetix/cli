# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_413

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-413",
	"name": "Improper Resource Locking",
	"description": "Reports Java code that believes it holds exclusive access but may not, or that cannot reliably give it up. (1) `x.tryLock(...)` as a bare statement: the result is discarded, so the code proceeds whether or not it got the lock (java.util.concurrent locks and FileChannel). (2) `synchronized (new ...)`: every thread locks a fresh object, so nothing is excluded. (3) `x.lock()` / `x.lockInterruptibly()` on a java.util.concurrent Lock (a field or local declared Lock/ReentrantLock/ReadWriteLock/ReentrantReadWriteLock, or `rw.readLock()`/`rw.writeLock()`) whose unlock in the same method is not in a finally block, or that is never unlocked anywhere in the file: an exception leaves the lock held and every later caller blocks. Not reported: lock() followed by try { ... } finally { x.unlock(); }, a checked or assigned tryLock result, a lock taken in one method and released in another (acquire/close pairs), lock() on types that are not concurrency locks, test files, comments and strings. Kotlin withLock and locks passed between objects are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-413/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [413],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-resource-locking", "cwe-413"],
}

_strip(l) := regex.replace(l, `"(\\.|[^"\\])*"`, `""`)

_report(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_esc(v) := regex.replace(v, `([.()])`, `\$1`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "tryLock(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "tryLock(")
	not helpers.is_comment_line(line)
	regex.match(`^\s*(this\.)?[\w.]+(\(\))?\.tryLock\([^;]*\)\s*;`, _strip(line))
	finding := _report(path, i, line, "The result of tryLock() is discarded, so the code below runs whether or not the lock was obtained. Test it: if (lock.tryLock()) { try { ... } finally { lock.unlock(); } }.")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "synchronized")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "synchronized")
	not helpers.is_comment_line(line)
	regex.match(`\bsynchronized\s*\(\s*new\s+[\w.<>]+\s*\(`, _strip(line))
	finding := _report(path, i, line, "synchronized (new ...) locks an object no other thread can see, so it provides no mutual exclusion. Synchronize on a private final field shared by every caller.")
}

_lock_types := `(?:Lock|ReentrantLock|ReadWriteLock|ReentrantReadWriteLock)`

# The receiver is a java.util.concurrent lock.
_is_lock(_, recv) if regex.match(`\.(readLock|writeLock)\(\)$`, recv)

_is_lock(content, recv) if {
	not regex.match(`\(\)$`, recv)
	v := regex.replace(recv, `^this\.`, "")
	regex.match(concat("", [`\b`, _lock_types, `(<[^>]*>)?\s+`, v, `\s*[=;]|\b`, v, `\s*=\s*new\s+Reentrant`]), content)
}

# End of the enclosing method: the next member declaration, or 60 lines.
_method_end(lines, i) := e if {
	hi := min([count(lines), i + 60])
	ends := [k |
		some k in numbers.range(i + 1, hi - 1)
		regex.match(`^\s*(@\w+|(public|private|protected|static|final|synchronized)\s[^;=]*\(.*\{?\s*$)`, lines[k])
	]
	e := min(array.concat([hi], ends))
}

_unlock_re(recv) := concat("", [`(^|[^\w.])`, _esc(regex.replace(recv, `^this\.`, "")), `\.unlock\(\s*\)`])

_unlock_lines(lines, lo, hi, recv) := [k |
	some k in numbers.range(lo, hi - 1)
	k < hi
	contains(lines[k], "unlock")
	regex.match(_unlock_re(recv), regex.replace(lines[k], `\bthis\.`, ""))
]

_in_finally(lines, k) if {
	some j in numbers.range(max([0, k - 4]), k)
	regex.match(`\bfinally\b`, lines[j])
}

# A longer finally block: the nearest line above at a shallower indent (the
# block's opener) is the finally.
_in_finally(lines, k) if {
	kind := _indent(lines[k])
	opens := [j |
		some j in numbers.range(max([0, k - 15]), k - 1)
		trim_space(lines[j]) != ""
		_indent(lines[j]) < kind
	]
	count(opens) > 0
	regex.match(`\bfinally\b`, lines[max(opens)])
}

_indent(l) := count(l) - count(trim_left(l, " \t"))

_improper(lines, content, i, recv) if {
	e := _method_end(lines, i)
	ks := _unlock_lines(lines, i + 1, e, recv)
	count(ks) > 0
	not _some_in_finally(lines, ks)
}

_improper(lines, content, i, recv) if {
	e := _method_end(lines, i)
	count(_unlock_lines(lines, i + 1, e, recv)) == 0
	not regex.match(_unlock_re(recv), regex.replace(helpers.code_text(lines), `\bthis\.`, ""))
}

_some_in_finally(lines, ks) if {
	some k in ks
	_in_finally(lines, k)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "Lock")
	regex.match(`\.lock(Interruptibly)?\(\s*\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".lock")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^\s*((?:this\.)?\w+(?:\.(?:readLock|writeLock)\(\))?)\.lock(?:Interruptibly)?\(\s*\)\s*;`, _strip(line), 1)
	count(m) > 0
	recv := m[0][1]
	_is_lock(content, recv)
	_improper(lines, content, i, recv)
	finding := _report(path, i, line, sprintf("'%s' is locked here but not released in a finally block: if anything below throws, the lock stays held and every later caller blocks. Use %s.lock(); try { ... } finally { %s.unlock(); }.", [recv, recv, recv]))
}
