# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_765

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-765",
	"name": "Lock released twice for one acquisition",
	"description": "A lock is released a second time without being re-acquired in between. Java's ReentrantLock and ReentrantReadWriteLock throw IllegalMonitorStateException; Go's sync.Mutex and RWMutex crash the program with a fatal 'unlock of unlocked mutex'. Reported: (1) two unlock()/Unlock()/RUnlock() statements on the same lock in one block (or the second in a block nested inside the first's) with no lock()/Lock()/RLock() of it in between; (2) Java: an unlock() inside a try block (including one on an early-return branch) whose finally block, multi-line or a one-line `} finally { lock.unlock(); }`, unlocks the same lock again; (3) Go: an explicit Unlock()/RUnlock() in the block that already defers the same release (or a block nested in it), when the function does not re-acquire the lock after it. Not reported: an unlock on an early-exit branch followed by the main unlock outside that branch, a release followed by re-acquisition (unlock, wait, lock), switch cases and if/else branches that each release once, different locks, a release inside a goroutine, lambda or anonymous class, a defer inside a func literal followed by an explicit release after the literal, releases in different functions, comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-765/",
	"languages": ["java", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [765],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["concurrency", "lock", "multiple-unlock", "cwe-765"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_q(s) := regex.replace(s, `([.\[\]()])`, `\$1`)

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_gate("go") := `\.R?Unlock\(\)`

_gate("java") := `\.unlock\(\)`

# The released lock's key: the Go receiver, or the Java receiver with its
# readLock()/writeLock() view.
_unlock("go", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_][\w.\[\]]*)\.R?Unlock\(\)\s*(?://.*)?$`, line, 1)
	count(m) > 0
}

_unlock("java", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_][\w.]*?(?:\.readLock\(\)|\.writeLock\(\))?)\.unlock\(\)\s*;`, line, 1)
	count(m) > 0
}

# } finally { lock.unlock(); }
_unlock("java", line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*\}\s*finally\s*\{\s*([A-Za-z_][\w.]*?(?:\.readLock\(\)|\.writeLock\(\))?)\.unlock\(\)\s*;\s*\}\s*$`, line, 1)
	count(m) > 0
}

_lock_re("go", key) := concat("", [`\b`, _q(key), `\.R?Lock\(\)`])

_lock_re("java", key) := concat("", [`\b`, _q(key), `\.lock(?:Interruptibly)?\(\)|\b`, _q(key), `\.tryLock\(`])

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	regex.match(_gate(lang), content)
	lines := split(content, "\n")
	rels := [[i, k] | some i, line in lines; regex.match(_gate(lang), line); k := _unlock(lang, line)]
	count(rels) > 1
	some a in rels
	some b in rels
	i := a[0]
	j := b[0]
	j > i
	j - i <= 80
	a[1] == b[1]
	not _relocked_between(lines, i, j, _lock_re(lang, a[1]))
	not _closure_between(lines, i, j)
	_double(lang, lines, i, j)
	finding := _finding(path, lines, j, a[1], i)
}

# Go: defer q.mu.Unlock() ... q.mu.Unlock() with no re-lock afterwards.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "defer ")
	regex.match(_gate("go"), content)
	lines := split(content, "\n")
	some d, dl in lines
	contains(dl, "defer ")
	m := regex.find_all_string_submatch_n(`^\s*defer\s+([A-Za-z_][\w.\[\]]*)\.(R?Unlock)\(\)`, dl, 1)
	count(m) > 0
	key := m[0][1]
	e := _fn_end(lines, d)
	explicit := concat("", [`^\s*`, _q(key), `\.`, m[0][2], `\(\)`])
	some u in numbers.range(d + 1, e)
	u >= d + 1
	u <= e
	regex.match(explicit, lines[u])
	not _closure_between(lines, d, u + 1)
	# The explicit release is still inside the block that deferred: a defer in
	# a func literal (func() { mu.Lock(); defer mu.Unlock() }()) has run by the
	# time the code after the literal's closing brace unlocks again.
	not _shallower_between(lines, d, u, _indent(dl))
	not _relocked_between(lines, u, e + 1, _lock_re("go", key))
	finding := _finding(path, lines, u, key, d)
}

_finding(path, lines, j, key, first) := {
	"rule_id": metadata.id,
	"message": sprintf("%s is released again without being re-acquired (already released by line %d): a second unlock throws IllegalMonitorStateException in Java and is a fatal error in Go. Release each acquisition exactly once", [key, first + 1]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": j + 1,
	"snippet": lines[j],
}

# (1) both releases in one block, the second possibly nested deeper.
_double(_, lines, i, j) if {
	ii := _indent(lines[i])
	_indent(lines[j]) >= ii
	not _shallower_between(lines, i, j, ii)
}

# (2) Java: release inside try { }, release again in its finally { }.
_double("java", lines, i, j) if {
	ii := _indent(lines[i])
	some f in numbers.range(i + 1, j - 1)
	f >= i + 1
	f <= j - 1
	regex.match(`^\s*\}\s*finally\s*\{`, lines[f])
	fi := _indent(lines[f])
	fi < ii
	_indent(lines[j]) > fi
	not _shallower_between(lines, f, j, fi + 1)
	_try_owns(lines, i, f, fi)
}

# (2b) Java: release inside try { }, then a one-line } finally { x.unlock(); }.
_double("java", lines, i, j) if {
	regex.match(`^\s*\}\s*finally\s*\{`, lines[j])
	ii := _indent(lines[i])
	fi := _indent(lines[j])
	fi < ii
	not _shallower_between(lines, i, j, fi + 1)
	_try_owns(lines, i, j, fi)
}

# The finally at line f belongs to a try opened above line i at the same
# indentation, and only catch clauses sit at that level in between.
_try_owns(lines, i, f, fi) if {
	ts := [t |
		some t in numbers.range(max([0, i - 80]), i - 1)
		t >= max([0, i - 80])
		t <= i - 1
		_indent(lines[t]) == fi
		regex.match(`^\s*try\s*(?:\(.*\))?\s*\{\s*$`, lines[t])
	]
	count(ts) > 0
	t := max(ts)
	not _other_at_level(lines, t, f, fi)
}

_other_at_level(lines, t, f, fi) if {
	some k in numbers.range(t + 1, f - 1)
	k >= t + 1
	k <= f - 1
	trim_space(lines[k]) != ""
	_indent(lines[k]) <= fi
	not regex.match(`^\s*\}\s*catch\b`, lines[k])
}

_shallower_between(lines, i, j, ii) if {
	some k in numbers.range(i + 1, j - 1)
	k >= i + 1
	k <= j - 1
	trim_space(lines[k]) != ""
	_indent(lines[k]) < ii
}

_relocked_between(lines, i, j, re) if {
	some k in numbers.range(i + 1, j - 1)
	k >= i + 1
	k <= j - 1
	regex.match(re, lines[k])
}

_closure_between(lines, i, j) if {
	some k in numbers.range(i + 1, j - 1)
	k >= i + 1
	k <= j - 1
	regex.match(`\bfunc\s*\(|->\s*\{|\bnew\s+[\w.<>]+\s*\([^)]*\)\s*\{`, lines[k])
	not helpers.is_comment_line(lines[k])
}

# The end of the enclosing top-level Go function: the next column-0 brace.
_fn_end(lines, d) := e if {
	ends := [k | some k in numbers.range(d + 1, min([count(lines) - 1, d + 400])); k > d; startswith(lines[k], "}")]
	e := min(array.concat(ends, [min([count(lines) - 1, d + 400])]))
}
