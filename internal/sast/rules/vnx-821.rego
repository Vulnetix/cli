# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_821

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-821",
	"name": "Incorrect Synchronization",
	"description": "Java code synchronizes, but on a monitor that does not give the intended mutual exclusion. Reported: synchronized (new X()) (a fresh lock each call, so nothing is excluded); synchronized on a local variable assigned new ... in the same method; synchronized (Thread.currentThread()) (each thread locks itself); synchronized on a string literal, Boolean.TRUE/FALSE, Integer/Long/String.valueOf or .intern(), or a String/Integer/Long/Short/Byte/Boolean/Character field or variable, final or not (interned and cached values are shared with unrelated code); synchronized (getClass()) (a subclass instance locks a different Class object); synchronized on a java.util.concurrent Lock/ReentrantLock/ReadWriteLock/StampedLock/Semaphore object, field or local (its intrinsic monitor is unrelated to lock()/unlock()); synchronized on a non-final field that a method other than a constructor reassigns (threads end up holding different monitors); and a write to a static non-final field inside a non-static synchronized method, which locks the instance while the data is shared by every instance. Not reported: synchronized (this), on a final Object or collection field, on X.class, on a non-final field assigned only in a constructor, on a local obtained from a shared map or a lock-stripe array, static synchronized methods, a static write inside a synchronized (X.class) block, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-821/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [821],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["lock-sync", "cwe-821", "concurrency"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_sync_re := `^\s*(?:\}\s*)?synchronized\s*\(\s*(.+?)\s*\)\s*(?:\{.*)?$`

_boxed := `(?:String|Integer|Long|Short|Byte|Boolean|Character|Double|Float)`

_locks := `(?:ReentrantLock|Lock|ReadWriteLock|ReentrantReadWriteLock|StampedLock|Semaphore)`

# The indent of class members: the shallowest line carrying an access modifier.
_member_indent(lines) := min(array.concat([4], [_indent(l) |
	some l in lines
	regex.match(`^\s+(?:public|private|protected)\s`, l)
]))

_bad_monitor(expr, _, _, _, _) := "a new object" if regex.match(`^new\s+[\w.<>]+\s*\(`, expr)

_bad_monitor(expr, _, _, _, _) := "a string literal" if startswith(expr, `"`)

_bad_monitor(expr, _, _, _, _) := "a cached boxed value" if {
	regex.match(`^(?:Boolean\.(?:TRUE|FALSE)|(?:Integer|Long|Short|Byte|Character|Boolean|String)\.valueOf\s*\(|.*\.intern\(\)$)`, expr)
}

_bad_monitor(expr, _, _, _, _) := "getClass()" if regex.match(`^(?:this\.)?getClass\(\)$`, expr)

_bad_monitor(expr, _, _, _, _) := "the current thread" if regex.match(`^Thread\.currentThread\(\)$`, expr)

_bad_monitor(expr, _, _, content, _) := "an interned String or cached boxed value" if {
	n := _name(expr)
	regex.match(concat("", [`\b`, _boxed, `\s+`, n, `\s*[=;]`]), content)
}

_bad_monitor(expr, _, _, content, _) := "a java.util.concurrent lock's intrinsic monitor" if {
	n := _name(expr)
	regex.match(concat("", [`\b`, _locks, `\s+`, n, `\s*[=;]`]), content)
}

# A local created in this method.
_bad_monitor(expr, lines, i, _, mi) := "a lock object created locally" if {
	n := _name(expr)
	re := concat("", [`^\s*(?:final\s+)?[\w.<>\[\]]+\s+`, n, `\s*=\s*new\s`])
	some j in numbers.range(max([0, i - 25]), i - 1)
	regex.match(re, lines[j])
	_indent(lines[j]) > mi
	not _member_closed(lines, j, i, mi)
}

# A non-final field reassigned in a method.
_bad_monitor(expr, lines, _, content, mi) := "a non-final field that is reassigned" if {
	n := _name(expr)
	decl := concat("", [`^\s*(?:(?:private|protected|public|static|transient)\s+)*[\w.<>\[\]]+\s+`, n, `\s*(?:=[^;]*)?;\s*$`])
	some j, l in lines
	_indent(l) == mi
	regex.match(decl, l)
	not contains(l, "final ")
	assign := concat("", [`^\s*(?:this\.)?`, n, `\s*=[^=]`])
	some k, l2 in lines
	_indent(l2) > mi
	regex.match(assign, l2)
	not _in_ctor(lines, k, mi, content)
}

_name(expr) := n if {
	m := regex.find_all_string_submatch_n(`^(?:this\.)?([A-Za-z_]\w*)$`, expr, 1)
	n := m[0][1]
}

# A member at indent mi closes between lines a and b.
_member_closed(lines, a, b, mi) if {
	some k in helpers.span(a + 1, b - 1)
	_indent(lines[k]) <= mi
	startswith(trim_space(lines[k]), "}")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "synchronized")
	lines := split(content, "\n")
	mi := _member_indent(lines)
	some i, line in lines
	contains(line, "synchronized")
	m := regex.find_all_string_submatch_n(_sync_re, line, 1)
	count(m) > 0
	what := _bad_monitor(trim_space(m[0][1]), lines, i, content, mi)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("synchronized on %s: threads do not share this monitor the way the code assumes, so the block does not exclude them. Lock on a private final Object field (or use the Lock's lock()/unlock())", [what]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A non-static synchronized method writing a static non-final field.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "synchronized")
	contains(content, "static")
	lines := split(content, "\n")
	mi := _member_indent(lines)
	statics := {n |
		some l in lines
		_indent(l) == mi
		contains(l, "static ")
		not contains(l, "final ")
		mm := regex.find_all_string_submatch_n(`^\s*(?:(?:private|protected|public|static|transient|volatile)\s+)*[\w.<>\[\]]+\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?;\s*$`, l, 1)
		count(mm) > 0
		n := mm[0][1]
	}
	count(statics) > 0
	some s, decl in lines
	_indent(decl) == mi
	regex.match(`\bsynchronized\b[^(]*\(`, decl)
	not regex.match(`\bstatic\b`, decl)
	some i in numbers.range(s + 1, min([count(lines) - 1, s + 60]))
	line := lines[i]
	_indent(line) > mi
	not helpers.is_comment_line(line)
	not _member_closed(lines, s, i, mi)
	not _in_class_lock(lines, s, i)
	some n in statics
	regex.match(concat("", [`(?:^|[^\w.])(?:\w+\.)?`, n, `\s*(?:\+\+|--|[+\-*/%|&^]?=[^=])|(?:\+\+|--)\s*(?:\w+\.)?`, n, `\b`]), line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Static field '%s' is written under an instance lock (a non-static synchronized method): two instances hold different monitors and race on the shared field. Make the method static synchronized or lock on a static final object", [n]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Line k is inside a constructor of the class: the nearest member declaration
# above it names the class.
_in_ctor(lines, k, mi, content) if {
	m := regex.find_all_string_submatch_n(`\bclass\s+([A-Za-z_]\w*)`, content, 1)
	cls := m[0][1]
	cands := [c |
		some c in numbers.range(max([0, k - 80]), k - 1)
		l := lines[c]
		_indent(l) == mi
		t := trim_space(l)
		t != ""
		not startswith(t, "}")
		not startswith(t, "@")
		not startswith(t, "//")
		not startswith(t, "*")
		not startswith(t, "/*")
	]
	count(cands) > 0
	regex.match(concat("", [`^\s*(?:(?:public|protected|private)\s+)?`, cls, `\s*\(`]), lines[max(cands)])
}

# Line i sits inside a synchronized (X.class) block opened after line s.
_in_class_lock(lines, s, i) if {
	some k in helpers.span(s + 1, i - 1)
	regex.match(`^\s*synchronized\s*\(\s*[\w.]+\.class\s*\)`, lines[k])
	ik := _indent(lines[k])
	_indent(lines[i]) > ik
	not _block_closed(lines, k, i, ik)
}

_block_closed(lines, k, i, ik) if {
	some m in helpers.span(k + 1, i - 1)
	_indent(lines[m]) <= ik
	startswith(trim_space(lines[m]), "}")
}
