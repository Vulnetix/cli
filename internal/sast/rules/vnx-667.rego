# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_667

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-667",
	"name": "Improper locking: shared String/boxed monitor or Lock released outside finally",
	"description": "Java locking that does not protect what it claims to. Reported: (1) a synchronized block whose monitor is a String literal, an .intern()ed string, Boolean.TRUE/FALSE, a boxed valueOf(...) value, or a field, variable or method parameter this file declares as String, Boolean, Integer, Long, Short, Byte or Character (a String parameter used for per-key locking excludes nothing: equal keys are different objects unless interned, and then shared JVM-wide); interned strings and cached boxes are shared across the whole JVM (unrelated code contends on, or deadlocks with, the same monitor) and a boxed field reassigned inside the block changes the monitor under the lock; (2) a statement lock.lock() / lockInterruptibly() (including rw.readLock().lock()) on a java.util.concurrent Lock with no finally block that calls the same receiver's unlock() in the following 60 lines, so an exception thrown in the critical section leaves the lock held forever. Not reported: synchronized on this, a class literal or a private Object/other field, try { lock.lock(); ... } finally { lock.unlock(); } in either order, tryLock(), FileChannel.lock() assignments, methods that are themselves named lock/acquire (wrappers), test files for the Lock shape, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-667/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [667],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-locking", "cwe-667", "java", "concurrency"],
}

_sync_re := `^\s*(?:\}\s*)?synchronized\s*\((.*)\)\s*\{?\s*$`

_shared_monitor(expr, _) if regex.match(`^\s*"`, expr)

_shared_monitor(expr, _) if regex.match(`\.intern\(\)\s*$`, expr)

_shared_monitor(expr, _) if regex.match(`^\s*Boolean\.(?:TRUE|FALSE)\s*$`, expr)

_shared_monitor(expr, _) if regex.match(`^\s*(?:Integer|Long|Short|Byte|Character|Boolean)\.valueOf\(`, expr)

# A plain name (or this.name) whose declaration in this file is a String or a box.
_shared_monitor(expr, content) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:this\.)?([A-Za-z_]\w*)\s*$`, expr, 1)
	name := m[0][1]
	regex.match(concat("", [`(?m)^[^/*\n]*\b(?:String|Boolean|Integer|Long|Short|Byte|Character)\s+`, name, `\s*[=;]`]), content)
}

# A method parameter declared as a String or a box: equal values are not the
# same object (per-key locking that excludes nothing) or are interned/cached.
_shared_monitor(expr, content) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*$`, expr, 1)
	name := m[0][1]
	regex.match(concat("", [`(?m)^[^/*\n]*[(,]\s*(?:(?:final|@\w+)\s+)*(?:String|Boolean|Integer|Long|Short|Byte|Character)\s+`, name, `\s*[,)]`]), content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "synchronized")
	regex.match(`(?m)^\s*(?:\}\s*)?synchronized\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "synchronized")
	m := regex.find_all_string_submatch_n(_sync_re, line, 1)
	expr := m[0][1]
	_shared_monitor(expr, content)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("synchronized on '%s', an interned String or a cached/boxed value shared across the JVM (or reassigned under the lock); synchronize on a private final Object instead", [trim_space(expr)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_lock_re := `^\s*((?:this\.)?[A-Za-z_][\w\.]*(?:\.(?:readLock|writeLock)\(\))?)\.(?:lock|lockInterruptibly)\(\)\s*;`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "ock()")
	not helpers.is_test_path(path)
	regex.match(concat("", [`(?m)`, _lock_re]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ock")
	m := regex.find_all_string_submatch_n(_lock_re, line, 1)
	recv := m[0][1]
	not _in_wrapper(lines, i)
	not _finally_unlocks(lines, i, recv)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is acquired without a finally block that releases it: an exception in the critical section leaves the lock held. Use lock(); try { ... } finally { unlock(); }", [recv]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A finally (within the next 60 lines, or a try opened just above) whose
# body calls this receiver's unlock().
_finally_unlocks(lines, i, recv) if {
	unlock := concat("", [recv, ".unlock()"])
	n := count(lines) - 1
	some f in numbers.range(i + 1, min([n, i + 60]))
	contains(lines[f], "finally")
	regex.match(`\bfinally\b`, lines[f])
	some u in numbers.range(f, min([n, f + 10]))
	contains(lines[u], unlock)
	not helpers.is_comment_line(lines[u])
}

# The enclosing method is itself a lock/acquire wrapper.
_in_wrapper(lines, i) if {
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`\b(?:void|boolean)\s+(?:lock|acquire|lockInterruptibly|enter|begin)\w*\s*\(`, lines[j])
}
