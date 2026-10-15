# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_764

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-764",
	"name": "Lock acquired again while it is already held",
	"description": "The same lock is acquired a second time, in the same block or a block nested inside it, while the first acquisition is still held (no release of that lock in between). Go: <recv>.Lock() or <recv>.RLock() followed by another Lock() or RLock() on the same receiver deadlocks (sync.Mutex is not reentrant, an RWMutex cannot be upgraded, and recursive read locking is prohibited); a deferred Unlock does not release it in time. Java: ReentrantLock lock()/lockInterruptibly() twice leaves a hold count the single unlock() does not clear, and rw.readLock().lock() followed by rw.writeLock().lock() deadlocks because ReentrantReadWriteLock cannot upgrade. Not reported: an Unlock/RUnlock/unlock() of that lock between the two acquisitions (a Java one-line `} finally { lock.unlock(); }` counts), acquisitions in sibling branches (if/else), in a goroutine, lambda or anonymous class opened in between, a different lock, tryLock(), Java write-to-read downgrade, acquisitions in different functions, comments and test files. Locks reached through a helper call are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-764/",
	"languages": ["java", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [764],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["concurrency", "lock", "multiple-lock-same-resource", "cwe-764"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A lock statement: [base, mode] where mode is "w" (exclusive), "r" (shared)
# or "x" (Java plain lock, mode irrelevant).
_go_lock := `^\s*([A-Za-z_][\w.\[\]]*)\.(Lock|RLock)\(\)\s*(?://.*)?$`

_go_unlock(base) := concat("", [`^\s*`, _q(base), `\.R?Unlock\(\)`])

_java_lock := `^\s*([A-Za-z_][\w.]*?)(\.readLock\(\)|\.writeLock\(\))?\.(lock|lockInterruptibly)\(\)\s*;`

# Not anchored: a one-line `} finally { lock.unlock(); }` releases too.
_java_unlock(base) := concat("", [`(?:^|[^\w.])`, _q(base), `(?:\.readLock\(\)|\.writeLock\(\))?\.unlock\(\)\s*;`])

_q(s) := regex.replace(s, `([.\[\]])`, `\$1`)

_lock("go", line) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(_go_lock, line, 1)
	count(m) > 0
}

_lock("java", line) := [m[0][1], _java_mode(m[0][2])] if {
	m := regex.find_all_string_submatch_n(_java_lock, line, 1)
	count(m) > 0
}

_java_mode(".readLock()") := "r"

_java_mode(".writeLock()") := "w"

_java_mode("") := "x"

_unlock_re("go", base) := _go_unlock(base)

_unlock_re("java", base) := _java_unlock(base)

# Which second acquisitions conflict with the first.
_conflicts("go", _, _)

_conflicts("java", "x", "x")

_conflicts("java", "w", "w")

_conflicts("java", "r", "w")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_gate("go") := `\.R?Lock\(\)`

_gate("java") := `\.lock(?:Interruptibly)?\(\)`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	regex.match(_gate(lang), content)
	lines := split(content, "\n")
	locks := [[i, l] | some i, line in lines; regex.match(_gate(lang), line); l := _lock(lang, line)]
	count(locks) > 1
	some a in locks
	some b in locks
	i := a[0]
	j := b[0]
	j > i
	j - i <= 60
	a[1][0] == b[1][0]
	_conflicts(lang, a[1][1], b[1][1])
	_same_block(lines, i, j)
	not _released_between(lines, i, j, _unlock_re(lang, a[1][0]))
	not _closure_between(lines, i, j)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is acquired again while it is still held (first acquired on line %d): this deadlocks or leaves a hold count that is never released. Release it first, or restructure so the lock is taken once", [a[1][0], i + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# Line j is in the block of line i or nested inside it: no code line between
# them is shallower than i (that would close i's block, or start a sibling
# branch such as `} else {`).
_same_block(lines, i, j) if {
	ii := _indent(lines[i])
	_indent(lines[j]) >= ii
	not _shallower_between(lines, i, j, ii)
}

_shallower_between(lines, i, j, ii) if {
	some k in numbers.range(i + 1, j - 1)
	k >= i + 1
	k <= j - 1
	trim_space(lines[k]) != ""
	_indent(lines[k]) < ii
}

_released_between(lines, i, j, re) if {
	some k in numbers.range(i + 1, j - 1)
	k >= i + 1
	k <= j - 1
	regex.match(re, lines[k])
}

# A goroutine, func literal, lambda or anonymous class opened in between runs
# the second acquisition elsewhere.
_closure_between(lines, i, j) if {
	some k in numbers.range(i + 1, j - 1)
	k >= i + 1
	k <= j - 1
	regex.match(`\bfunc\s*\(|->\s*\{|\bnew\s+[\w.<>]+\s*\([^)]*\)\s*\{`, lines[k])
	not helpers.is_comment_line(lines[k])
}
