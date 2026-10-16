# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_832

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-832",
	"name": "Unlock of a Resource that is not Locked",
	"description": "Reports a lock release that runs on a path where the lock may not be held. Java (java.util.concurrent Lock, including rw.readLock()/writeLock()): (1) an unlock() of a lock whose tryLock()/tryLock(timeout) result was discarded as a bare statement in the 40 lines above, so the unlock runs whether or not the lock was acquired; (2) an unlock() in a finally block whose try block acquires the same lock with lockInterruptibly() or tryLock(), so an interrupt, a failed tryLock or the early return/throw after it still reaches the unlock (IllegalMonitorStateException, masking the original exception); (3) an unlock() of a Lock/ReentrantLock/ReadWriteLock field or variable this file declares but never acquires (no lock/tryLock/lockInterruptibly on that name anywhere in the file) and never passes to other code as an argument. Python threading: release() after a bare acquire(blocking=False), acquire(False) or acquire(timeout=...) whose result was discarded. C/C++ pthreads: pthread_mutex_unlock/pthread_rwlock_unlock after a bare pthread_mutex_trylock/pthread_mutex_timedlock/pthread_rwlock_try*lock/timed*lock whose return value was discarded; C++ std::mutex/timed_mutex/shared_mutex m.unlock() (or unlock_shared()) after a bare try_lock()/try_lock_for()/try_lock_until() whose result was discarded. Not reported: lock() before try with unlock() in finally, if (lock.tryLock()) { try ... finally unlock }, an unlock guarded by an if on the same or the preceding line (if (acquired), isHeldByCurrentThread()), a tryLock/acquire whose result is assigned or tested, blocking acquire()/lock()/pthread_mutex_lock, locks released in a method of the same file other than the one that took them (begin/end pairs), a lock parameter (release(Lock l)), a lock handed to another object or returned from a getter, comments and string literals. Double unlocks are VNX-765.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-832/",
	"languages": ["java", "python", "c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [832],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unlock-not-locked", "cwe-832", "concurrency", "locking"],
}

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*(?:\s|/|$)|#)`, line)

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`), `//.*$|/\*.*?\*/|\s#.*$`, "")

_indent(line) := count(line) - count(trim_left(line, " \t"))

_esc(s) := regex.replace(s, `([.()\[\]*+?{}|^$\\])`, `\$1`)

# The release is conditional: an if on the same line, or the previous code
# line is an if header with no block of its own (if (got)\n unlock()).
_guarded(lines, u) if regex.match(`^\s*(?:\}\s*)?(?:finally\s*\{\s*)?(?:else\s+)?if\b`, _strip(lines[u]))

_guarded(lines, u) if {
	u > 0
	prev := _strip(lines[u - 1])
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?if\b|^\s*if\s.*:\s*$`, prev)
}

_guarded(lines, u) if {
	u > 1
	regex.match(`^\s*\{?\s*$`, lines[u - 1])
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?if\b`, _strip(lines[u - 2]))
}

# ---- Java ----------------------------------------------------------------

_java_recv := `([A-Za-z_][\w.]*(?:\(\))?(?:\.[A-Za-z_]\w*(?:\(\))?)*)`

_java_unlock_re := concat("", [`(?:^|[\s{;(])`, _java_recv, `\s*\.\s*unlock\s*\(\s*\)`])

_norm(recv) := trim_prefix(recv, "this.")

# Shape 1: a bare tryLock statement above the unlock.
_java_reason1(lines, u, recv) := sprintf("the result of %s.tryLock() on line %d is discarded, so this unlock runs even when the lock was not acquired", [recv, t + 1]) if {
	re := concat("", [`^\s*(?:this\.)?`, _esc(_norm(recv)), `\s*\.\s*tryLock\s*\([^;]*\)\s*;`])
	cands := [t |
		some t in numbers.range(max([0, u - 40]), u - 1)
		contains(lines[t], "tryLock")
		regex.match(re, lines[t])
		not _block_closed(lines, t, u)
	]
	count(cands) > 0
	t := max(cands)
}

# A line between t and u closes the block that holds line t (another method).
_block_closed(lines, t, u) if {
	some k in helpers.span(t + 1, u - 1)
	regex.match(`^\s*\}\s*$`, lines[k])
	_indent(lines[k]) < _indent(lines[t])
}

# Shape 2: the unlock is in a finally whose try acquires interruptibly or by tryLock.
_java_reason2(lines, u, recv) := sprintf("the try block that this finally closes acquires %s on line %d with %s, which can fail or be skipped, and the finally still unlocks it; acquire the lock before try", [recv, a + 1, how]) if {
	f := _finally_line(lines, u)
	t := _try_line(lines, f)
	re := concat("", [`(?:^|[^\w.])(?:this\.)?`, _esc(_norm(recv)), `\s*\.\s*(tryLock|lockInterruptibly)\s*\(`])
	cands := [[a, m[0][1]] |
		some a in numbers.range(t, f)
		contains(lines[a], "ock")
		not _is_comment(lines[a])
		m := regex.find_all_string_submatch_n(re, _strip(lines[a]), 1)
		count(m) > 0
	]
	count(cands) > 0
	a := cands[0][0]
	how := concat("", [cands[0][1], "()"])
}

# Shape 3: no line of the file acquires this lock.
# Only for a lock field or variable this file declares, which no line of
# the file acquires and which is never handed to other code as an argument.
_java_reason3(lines, _, recv) := sprintf("nothing in this file locks %s, so this unlock releases a lock the code never took", [recv]) if {
	name := split(_norm(recv), ".")[0]
	regex.match(`^[A-Za-z_]\w*$`, name)
	_any_match(lines, concat("", [`\b(?:ReentrantLock|ReentrantReadWriteLock|ReadWriteLock|Lock)\s+`, name, `\s*[=;]`]), name)
	not _any_match(lines, concat("", [`(?:^|[^\w])`, name, `(?:\s*\.\s*(?:readLock|writeLock)\s*\(\s*\))?\s*\.\s*(?:lock|tryLock|lockInterruptibly)\s*\(`]), "ock")
	not _any_match(lines, concat("", [`[(,]\s*(?:this\.)?`, name, `\s*[,)]`]), name)
	not _any_match(lines, concat("", [`\breturn\s+(?:this\.)?`, name, `\s*;`]), name)
}

_any_match(lines, re, word) if {
	some l in lines
	contains(l, word)
	regex.match(re, _strip(l))
}

# The finally block holding line u: `finally {` on u itself or within the
# four lines above with no block closed in between.
_finally_line(lines, u) := f if {
	cands := [k |
		some k in numbers.range(max([0, u - 4]), u)
		regex.match(`\bfinally\b`, lines[k])
	]
	count(cands) > 0
	f := max(cands)
}

# The try opening at the indentation of the finally line.
_try_line(lines, f) := t if {
	fi := _indent(lines[f])
	cands := [k |
		some k in numbers.range(max([0, f - 80]), f - 1)
		_indent(lines[k]) == fi
		regex.match(`^\s*try\s*(?:\(|\{|$)`, lines[k])
	]
	count(cands) > 0
	t := max(cands)
}

_java_hit(lines, u, line) := [recv, reason] if {
	m := regex.find_all_string_submatch_n(_java_unlock_re, _strip(line), 1)
	count(m) > 0
	recv := m[0][1]
	reasons := {r | r := _java_reason1(lines, u, recv)} | {r | r := _java_reason2(lines, u, recv)} | {r | r := _java_reason3(lines, u, recv)}
	count(reasons) > 0
	reason := sort(reasons)[0]
}

# ---- Python ---------------------------------------------------------------

_py_hit(lines, u, line) := [recv, reason] if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_][\w.]*)\.release\(\s*\)\s*$`, _strip(line), 1)
	count(m) > 0
	recv := m[0][1]
	re := concat("", [`^\s*`, _esc(recv), `\.acquire\(\s*(?:False\b|blocking\s*=\s*False|timeout\s*=|[^)]*,\s*timeout\s*=|[^)]*,\s*[0-9.]+\s*\))[^)]*\)\s*$`])
	cands := [t |
		some t in numbers.range(max([0, u - 40]), u - 1)
		contains(lines[t], "acquire")
		regex.match(re, _strip(lines[t]))
	]
	count(cands) > 0
	t := max(cands)
	reason := sprintf("the result of the non-blocking %s.acquire() on line %d is discarded, so this release runs even when the lock was not acquired", [recv, t + 1])
}

# ---- C / C++ --------------------------------------------------------------

_c_try := {
	"pthread_mutex_unlock": `pthread_mutex_(?:trylock|timedlock|clocklock)`,
	"pthread_rwlock_unlock": `pthread_rwlock_(?:tryrdlock|trywrlock|timedrdlock|timedwrlock|clockrdlock|clockwrlock)`,
}

_c_hit(lines, u, line) := [arg, reason] if {
	m := regex.find_all_string_submatch_n(`\b(pthread_mutex_unlock|pthread_rwlock_unlock)\s*\(\s*(&?\s*[A-Za-z_][\w.>\-]*)\s*\)`, _strip(line), 1)
	count(m) > 0
	arg := m[0][2]
	re := concat("", [`^\s*(?:\(void\)\s*)?(`, _c_try[m[0][1]], `)\s*\(\s*`, _esc(arg), `\s*[,)][^;]*;\s*$`])
	cands := [t |
		some t in numbers.range(max([0, u - 40]), u - 1)
		contains(lines[t], "pthread_")
		regex.match(re, _strip(lines[t]))
	]
	count(cands) > 0
	t := max(cands)
	reason := sprintf("the return value of the try/timed lock call on line %d is discarded, so this unlock runs even when the lock was not acquired", [t + 1])
}

# C++ std::mutex / std::timed_mutex / std::shared_mutex: m.unlock() after a
# bare m.try_lock() / try_lock_for() / try_lock_until() whose result was
# discarded (unlocking a mutex the thread does not own is undefined).
_c_hit(lines, u, line) := [recv, reason] if {
	m := regex.find_all_string_submatch_n(`(?:^|[\s{;(])([A-Za-z_][\w.]*(?:->[A-Za-z_]\w*)*)\s*(?:\.|->)\s*(unlock|unlock_shared)\s*\(\s*\)`, _strip(line), 1)
	count(m) > 0
	recv := m[0][1]
	try := {"unlock": `try_lock(?:_for|_until)?`, "unlock_shared": `try_lock_shared(?:_for|_until)?`}[m[0][2]]
	re := concat("", [`^\s*(?:\(void\)\s*)?`, _esc(recv), `\s*(?:\.|->)\s*`, try, `\s*\([^;]*\)\s*;\s*$`])
	cands := [t |
		some t in numbers.range(max([0, u - 40]), u - 1)
		contains(lines[t], "try_lock")
		regex.match(re, _strip(lines[t]))
	]
	count(cands) > 0
	t := max(cands)
	reason := sprintf("the result of %s.%s() on line %d is discarded, so this unlock runs even when the mutex was not acquired, which is undefined behaviour", [recv, trim_suffix(try, `(?:_for|_until)?`), t + 1])
}

# ---- driver ---------------------------------------------------------------

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_marker := {"java": "unlock()", "py": ".release()", "c": "unlock"}

_line_marker := {"java": "unlock", "py": ".release()", "c": "unlock"}

_gate := {"java": `\.\s*unlock\s*\(\s*\)`, "py": `\.acquire\(`, "c": `pthread_(?:mutex|rwlock)_(?:try|timed|clock)|\btry_lock`}

_hit("java", lines, u, line) := _java_hit(lines, u, line)

_hit("py", lines, u, line) := _py_hit(lines, u, line)

_hit("c", lines, u, line) := _c_hit(lines, u, line)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _marker[lang])
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some u, line in lines
	contains(line, _line_marker[lang])
	not _is_comment(line)
	not _guarded(lines, u)
	hit := _hit(lang, lines, u, line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is released on a path where it may not be held: %s", [hit[0], hit[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": u + 1,
		"snippet": line,
	}
}
