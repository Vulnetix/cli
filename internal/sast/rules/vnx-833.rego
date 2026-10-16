# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_833

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-833",
	"name": "Deadlock",
	"description": "Lock-order inversion in a Java file: one place acquires lock A and, while still holding it, acquires lock B, and another place in the same file acquires B and then A. Two threads taking the two paths at once each hold the lock the other is waiting for. Nested synchronized (x) blocks, instance synchronized methods (which hold this for their body) and explicit x.lock() calls (ReentrantLock and similar, held until x.unlock()) are read; the inner acquisition of each inverted pair is reported. Not reported: nested locks always taken in the same order, locks taken one after the other rather than nested, an inner lock taken inside a task handed to another thread (executor.submit(() -> {...}), new Thread, a TimerTask), tryLock(), static synchronized methods, inversions spread across different files, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-833/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [833],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["deadlock", "lock-ordering", "concurrency", "cwe-833"],
}

_sync_re := `^\s*synchronized\s*\(\s*([A-Za-z_][\w\.]*)\s*\)`

_lock_re := `^\s*([A-Za-z_][\w\.]*)\.lock\(\)\s*;`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# _acq(line) is [kind, lock] for a line that acquires a lock.
_acq(line) := ["sync", m[0][1]] if {
	contains(line, "synchronized")
	m := regex.find_all_string_submatch_n(_sync_re, line, 1)
	count(m) > 0
}

_acq(line) := ["lock", m[0][1]] if {
	contains(line, ".lock()")
	m := regex.find_all_string_submatch_n(_lock_re, line, 1)
	count(m) > 0
}

# An instance synchronized method holds the monitor of `this` for its body.
_acq(line) := ["sync", "this"] if {
	contains(line, "synchronized")
	regex.match(`^\s*(?:@\w+\s+)*(?:(?:public|protected|private|final)\s+)*synchronized\s+(?:(?:public|protected|private|final)\s+)*[\w<>\[\],?]+\s+\w+\s*\([^;]*$`, line)
}

# Code handed to another thread (executor.submit(() -> {, new Thread(() -> {,
# new TimerTask() {) between the two acquisitions and still open at the inner
# one: the inner lock is taken later, on that thread, not while holding the
# outer one.
_deferred(lines, i, j) if {
	j - 1 >= i + 1
	some m in helpers.span(i + 1, j - 1)
	regex.match(`\b(?:submit|execute|schedule\w*|runAsync|supplyAsync|invokeLater|post(?:Delayed)?|start)\s*\(|\bnew\s+(?:Thread|Runnable|Callable|TimerTask)\b`, lines[m])
	_indent(lines[m]) < _indent(lines[j])
	not _closed(lines, m, j, _indent(lines[m]))
}

# A block shallower than the outer acquisition closes between i and j: the
# outer lock (or its method) has ended.
_closed(lines, i, j, ii) if {
	j - 1 >= i + 1
	some m in helpers.span(i + 1, j - 1)
	_indent(lines[m]) <= ii
	startswith(trim_left(lines[m], " \t"), "}")
}

_still_held("sync", lines, i, j, _) if {
	_indent(lines[j]) > _indent(lines[i])
	not _closed(lines, i, j, _indent(lines[i]))
}

_still_held("lock", lines, i, j, x) if {
	unlock := concat("", [x, ".unlock()"])
	not _released(lines, i, j, unlock)
	not _method_left(lines, i, j, _indent(lines[i]))
}

_released(lines, i, j, unlock) if {
	j - 1 >= i + 1
	some m in helpers.span(i + 1, j - 1)
	contains(lines[m], unlock)
}

_method_left(lines, i, j, ii) if {
	j - 1 >= i + 1
	some m in helpers.span(i + 1, j - 1)
	_indent(lines[m]) < ii
	startswith(trim_left(lines[m], " \t"), "}")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?m)^\s*(synchronized\s*\(|[\w\.]+\.lock\(\))`, content)
	lines := split(content, "\n")
	acqs := [[i, a] | some i, l in lines; a := _acq(l)]
	count(acqs) > 1
	pairs := {[i, a[1], j, b[1]] |
		some p in acqs
		i := p[0]
		a := p[1]
		some q in acqs
		j := q[0]
		b := q[1]
		j > i
		j <= i + 40
		b[1] != a[1]
		_still_held(a[0], lines, i, j, a[1])
		not _deferred(lines, i, j)
	}
	some pr in pairs
	some other in pairs
	other[1] == pr[3]
	other[3] == pr[1]
	not helpers.is_comment_line(lines[pr[2]])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Lock-order inversion: '%s' is acquired while holding '%s', and elsewhere in this file '%s' is acquired while holding '%s'. Two threads can deadlock; always take the locks in one global order", [pr[3], pr[1], pr[1], pr[3]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": pr[2] + 1,
		"snippet": lines[pr[2]],
	}
}
