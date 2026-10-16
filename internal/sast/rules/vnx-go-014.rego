package vulnetix.rules.vnx_go_014

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-014",
	"name": "sync.Mutex or sync.RWMutex held across an exit without Unlock",
	"description": "A sync.Mutex.Lock() or sync.RWMutex.RLock() statement is left held: the function returns or panics (or, for a lock taken inside a loop, continues to the next iteration) between the lock and its first Unlock/RUnlock, or before the Unlock at the lock's own level on a path that no earlier Unlock in an enclosing block releases (one error branch unlocks, a later one forgets), or never unlocks at all, and no defer releases it. The mutex then stays locked, deadlocking the next caller. Not reported: an Unlock deferred anywhere in the function (or a defer func() whose body unlocks or releases; a deferred recover or log does not count), a short critical section with no exit before the Unlock, a return inside a func literal or a continue of a loop opened inside the critical section, a lock re-acquired after the function released it (sync.Cond-style unlock/wait/lock), a lock wrapper (a function named Lock/RLock/Acquire/Enter/Begin), a lock whose release lives in another function of the same file that unlocks without locking (Begin/Commit, start/end pairs), test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-014/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [667, 833],
	"capec": [],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["go", "mutex", "deadlock", "concurrency"],
}

# The statement is exactly `<receiver>.Lock()` or `.RLock()`. `if mu.TryLock()`,
# an assignment and a call as an argument are different shapes.
_lock_re := `^\s*([A-Za-z_][\w\.\[\]]*)\.(Lock|RLock)\(\)\s*$`

_unlock_name("Lock") := "Unlock"

_unlock_name("RLock") := "RUnlock"

_lock_name("Unlock") := "Lock"

_lock_name("RUnlock") := "RLock"

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Enclosing top-level function bounds, from the file's precomputed func and
# column-0 closing-brace lines.
_fn_start(starts, i) := max(array.concat([0], [s | some s in starts; s <= i]))

_fn_end(closers, i, n) := min(array.concat([n], [c | some c in closers; c > i]))

# The enclosing function's own name, so `func (c *C) Lock() { c.mu.Lock() }`
# (a wrapper whose caller is responsible for the Unlock) is not reported.
_in_lock_wrapper(lines, fs) if {
	regex.match(`^func\s+(\([^)]*\)\s*)?(?i:r?lock|acquire|enter|begin)\w*\s*\(`, lines[fs])
}

# A defer that releases this receiver anywhere in the function, or a
# `defer func() {` whose body releases a lock (the author's own release
# logic: if !unlocked { mu.Unlock() }, s.release()). A deferred recover or log
# releases nothing.
_deferred(lines, fs, e, unlock_expr) if {
	some j in numbers.range(fs, e)
	contains(lines[j], "defer ")
	contains(lines[j], unlock_expr)
	not helpers.is_comment_line(lines[j])
}

_deferred(lines, fs, e, _) if {
	some j in numbers.range(fs, e)
	regex.match(`^\s*defer\s+func\s*\(`, lines[j])
	some k in numbers.range(j, _defer_end(lines, j, e))
	regex.match(`(?i)unlock|release`, lines[k])
	not helpers.is_comment_line(lines[k])
}

# The line closing the deferred literal opened at j (its `}()` at j's indent).
_defer_end(lines, j, e) := c if {
	ij := _indent(lines[j])
	ends := [k |
		some k in numbers.range(j + 1, min([e, j + 40]))
		_indent(lines[k]) == ij
		startswith(trim_left(lines[k], " \t"), "}")
	]
	c := min(array.concat([min([e, j + 40])], ends))
}

# The function released this lock before taking it again (unlock, wait,
# re-lock): the lock belongs to the caller or to a defer above.
_reacquired(lines, fs, i, unlock_expr) if {
	i - 1 >= fs
	some j in numbers.range(fs, i - 1)
	contains(lines[j], unlock_expr)
	not helpers.is_comment_line(lines[j])
}

_first_unlock(lines, i, e, unlock_expr) := k if {
	i + 1 <= e
	cands := [j |
		some j in numbers.range(i + 1, e)
		contains(lines[j], unlock_expr)
		not helpers.is_comment_line(lines[j])
		not contains(lines[j], "defer ")
	]
	count(cands) > 0
	k := min(cands)
}

# Line j sits inside a block opened at k (k < j) and not closed before j.
_encloses(lines, k, j) if {
	ik := _indent(lines[k])
	_indent(lines[j]) > ik
	not _closed_between(lines, k, j, ik)
}

_closed_between(lines, k, j, ik) if {
	k + 1 <= j - 1
	some m in helpers.span(k + 1, j - 1)
	_indent(lines[m]) <= ik
	startswith(trim_left(lines[m], " \t"), "}")
}

# A func literal opened between the lock and line j encloses j: its return
# leaves the literal, not the locking function.
_in_func_literal(lines, i, j) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	regex.match(`\bfunc\s*\(`, lines[k])
	not startswith(lines[k], "func ")
	_encloses(lines, k, j)
}

# A loop opened between the lock and line j encloses j: its continue stays in
# the critical section.
_in_inner_loop(lines, i, j) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	regex.match(`^\s*for\b`, lines[k])
	_encloses(lines, k, j)
}

# The lock statement is inside a loop of this function.
_lock_in_loop(lines, fs, i) if {
	fs + 1 <= i - 1
	some k in helpers.span(fs + 1, i - 1)
	regex.match(`^\s*for\b`, lines[k])
	_encloses(lines, k, i)
}

# An exit between the lock and its first Unlock.
_exits_between(lines, fs, i, k) if {
	i + 1 <= k - 1
	some j in helpers.span(i + 1, k - 1)
	regex.match(`^\s*(return\b|panic\()`, lines[j])
	not _in_func_literal(lines, i, j)
}

_exits_between(lines, fs, i, k) if {
	i + 1 <= k - 1
	some j in helpers.span(i + 1, k - 1)
	regex.match(`^\s*continue\b`, lines[j])
	not _in_func_literal(lines, i, j)
	not _in_inner_loop(lines, i, j)
	_lock_in_loop(lines, fs, i)
}

# Another function of the file releases this field without locking it: the
# lock is handed over on purpose (Begin/Commit, writeStart/writeEnd).
_released_elsewhere(lines, starts, fs, field, unlock) if {
	re := concat("", [`\b`, field, `\.`, unlock, `\(\)`])
	lock_re := concat("", [`\b`, field, `\.`, _lock_name(unlock), `\(\)`])
	some k, l in lines
	contains(l, unlock)
	regex.match(re, l)
	not helpers.is_comment_line(l)
	ks := _fn_start(starts, k)
	ks != fs
	not _locks_in(lines, ks, k, lock_re)
}

_locks_in(lines, ks, k, lock_re) if {
	some m in numbers.range(ks, k)
	regex.match(lock_re, lines[m])
}

_field(recv) := f if {
	parts := split(recv, ".")
	f := regex.replace(parts[count(parts) - 1], `\[.*$`, "")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "Lock()")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	n := count(lines) - 1
	starts := [j | some j, l in lines; startswith(l, "func ")]
	closers := [j | some j, l in lines; startswith(l, "}")]
	some i, line in lines
	contains(line, "Lock()")
	m := regex.find_all_string_submatch_n(_lock_re, line, 1)
	count(m) > 0
	recv := m[0][1]
	unlock := _unlock_name(m[0][2])
	unlock_expr := concat("", [recv, ".", unlock, "()"])
	fs := _fn_start(starts, i)
	e := _fn_end(closers, i, n)
	not _in_lock_wrapper(lines, fs)
	not _deferred(lines, fs, e, unlock_expr)
	not _reacquired(lines, fs, i, unlock_expr)
	_leaks(lines, starts, fs, i, e, unlock_expr, _field(recv), unlock)
	finding := {
		"rule_id": metadata.id,
		"message": "Mutex Lock()/RLock() can be left held: the function returns or panics before the matching Unlock, or never unlocks. Use 'defer mu.Unlock()' immediately after locking",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# never unlocked in this function, and no other function is its release half
_leaks(lines, starts, fs, i, e, unlock_expr, field, unlock) if {
	not _first_unlock(lines, i, e, unlock_expr)
	not _released_elsewhere(lines, starts, fs, field, unlock)
}

# unlocked, but an exit comes first
_leaks(lines, _, fs, i, e, unlock_expr, _, _) if {
	k := _first_unlock(lines, i, e, unlock_expr)
	_exits_between(lines, fs, i, k)
}

# An early-exit branch unlocks, but a later exit before the lock-level Unlock
# does not: Lock; if !ok { Unlock; return }; if bad { return }; ...; Unlock.
_leaks(lines, _, fs, i, e, unlock_expr, _, _) if {
	k := _main_unlock(lines, i, e, unlock_expr)
	i + 1 <= k - 1
	some j in helpers.span(i + 1, k - 1)
	_exit_line(lines, fs, i, j)
	not _covered(lines, i, j, unlock_expr)
}

_exit_line(lines, _, i, j) if {
	regex.match(`^\s*(return\b|panic\()`, lines[j])
	not _in_func_literal(lines, i, j)
}

_exit_line(lines, fs, i, j) if {
	regex.match(`^\s*continue\b`, lines[j])
	not _in_func_literal(lines, i, j)
	not _in_inner_loop(lines, i, j)
	_lock_in_loop(lines, fs, i)
}

# The first Unlock at the lock statement's own nesting level, in the block
# the lock was taken in.
_main_unlock(lines, i, e, unlock_expr) := k if {
	i + 1 <= e
	il := _indent(lines[i])
	cands := [j |
		some j in numbers.range(i + 1, e)
		contains(lines[j], unlock_expr)
		_indent(lines[j]) == il
		not helpers.is_comment_line(lines[j])
		not contains(lines[j], "defer ")
	]
	count(cands) > 0
	k := min(cands)
	not _block_closed(lines, i, k, il)
}

# An Unlock above exit j whose block is still open at j releases the lock on
# that path.
_covered(lines, i, j, unlock_expr) if {
	i + 1 <= j - 1
	some u in helpers.span(i + 1, j - 1)
	contains(lines[u], unlock_expr)
	not helpers.is_comment_line(lines[u])
	not contains(lines[u], "defer ")
	not _block_closed(lines, u, j, _indent(lines[u]))
}

# The block holding line a (indent ia) ends before line b: a closing brace
# or a case/default label sits shallower between them.
_block_closed(lines, a, b, ia) if {
	a + 1 <= b - 1
	some m in helpers.span(a + 1, b - 1)
	_indent(lines[m]) < ia
	regex.match(`^\s*(?:\}|case\b|default\s*:)`, lines[m])
}
