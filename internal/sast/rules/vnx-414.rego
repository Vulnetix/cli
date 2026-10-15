# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_414

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-414",
	"name": "Missing Lock Check",
	"description": "A lock attempt that can fail without blocking is made and its result thrown away, so the code goes on to touch the shared resource whether or not the lock is held. Reported when the call is a whole statement (its result is not assigned, returned, tested or passed on): C/C++ pthread_mutex_trylock, pthread_rwlock_tryrdlock/trywrlock, pthread_spin_trylock, mtx_trylock, sem_trywait, pthread_mutex_timedlock, sem_timedwait, flock(fd, LOCK_EX or LOCK_SH with LOCK_NB), lockf(fd, F_TLOCK, ...), fcntl(fd, F_SETLK, ...); C++ mutex try_lock(), try_lock_for(), try_lock_until(), std::try_lock(a, b), and a std::unique_lock constructed with std::try_to_lock whose owns_lock() (or the lock object itself) is never tested in the next 10 lines; Go sync.Mutex/RWMutex TryLock()/TryRLock(); Java Lock.tryLock(...) and FileChannel.tryLock(...); Python threading Lock/RLock/Semaphore/Condition and multiprocessing locks .acquire(False), .acquire(blocking=False), .acquire(block=False) and .acquire with a finite timeout (timeout=..., or True plus a timeout). Not reported: a negative or None timeout (it waits forever), results that are assigned, returned or tested (if, while, ternary, &&), an explicit discard ((void) cast in C, _ = in Go), blocking lock calls (pthread_mutex_lock, flock without LOCK_NB, Lock()), unlocks (LOCK_UN), test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-414/",
	"languages": ["c", "cpp", "go", "java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [414],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-lock-check", "concurrency", "race-condition", "cwe-414"],
}

_lang(path) := "c" if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx"}
	endswith(path, ext)
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "py" if endswith(path, ".py")

# Whole-file gate.
_needle := {
	"c": `(?i)try_?(?:rd|wr)?lock|trywait|timed(?:lock|wait)|LOCK_NB|F_TLOCK|F_SETLK\b|try_to_lock`,
	"go": `\.TryR?Lock\(\)`,
	"java": `\.tryLock\(`,
	"py": `\.acquire\(`,
}

# A statement that is nothing but the lock attempt.
_bare_re := {
	"c": `^\s*(?:(?:std::)?(?:[A-Za-z_][\w\[\]]*(?:\.|->))*(?:try_lock|try_lock_for|try_lock_until)\s*\(.*\)|(?:std::)?(?:pthread_mutex_trylock|pthread_rwlock_tryrdlock|pthread_rwlock_trywrlock|pthread_spin_trylock|mtx_trylock|sem_trywait|pthread_mutex_timedlock|sem_timedwait)\s*\(.*|flock\s*\((?:.*\bLOCK_(?:EX|SH)\b.*\bLOCK_NB\b|.*\bLOCK_NB\b.*\bLOCK_(?:EX|SH)\b).*|lockf\s*\(\s*[^,]+,\s*F_TLOCK\b.*|fcntl\s*\(\s*[^,]+,\s*F_SETLK\s*,.*)\s*;?\s*$`,
	"go": `^\s*[A-Za-z_][\w\.\[\]\(\)]*\.TryR?Lock\(\)\s*(?://.*)?$`,
	"java": `^\s*(?:this\.)?[A-Za-z_][\w\.\[\]\(\)]*\.tryLock\s*\(.*\)\s*;\s*$`,
	"py": `^\s*(?:self\.)?[A-Za-z_][\w\.\[\]]*\.acquire\s*\(\s*(?:False\b[^)]*|0\s*(?:,[^)]*)?|block(?:ing)?\s*=\s*(?:False|0)\b[^)]*|timeout\s*=\s*[^-)\sN][^)]*|(?:block(?:ing)?\s*=\s*)?True\s*,\s*(?:timeout\s*=\s*[^-)\sN][^)]*|[^-)\sN=][^=)]*))\)\s*(?:#.*)?$`,
}

# A line that ends in the middle of an expression continues onto this one.
_continues(prev) if regex.match(`(?:[=(,!?+\-*/&|<>]|\breturn|\bnot|\band|\bor|\\)\s*$`, trim_space(prev))

_prev_code(lines, i) := l if {
	i > 0
	cands := [k |
		some k in numbers.range(max([0, i - 4]), i - 1)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
	]
	count(cands) > 0
	l := lines[cands[count(cands) - 1]]
}

_starts_statement(lines, i) if not _prev_code(lines, i)

_starts_statement(lines, i) if {
	p := _prev_code(lines, i)
	not _continues(p)
}

_strip(s) := regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_needle[lang], content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_needle[lang], line)
	not helpers.is_comment_line(line)
	regex.match(_bare_re[lang], _strip(line))
	_starts_statement(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The result of this non-blocking lock attempt is discarded: when the lock is already held the call fails and the code below touches the shared resource without it. Test the result (if (pthread_mutex_trylock(&m) == 0), if mu.TryLock(), if (lock.tryLock())) and only proceed when the lock was acquired",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# C++: std::unique_lock<...> lk(m, std::try_to_lock); never tested.
_try_to_lock_re := `\b(?:std::)?unique_lock\s*(?:<[^>]*>)?\s+([A-Za-z_]\w*)\s*[({][^;]*\btry_to_lock\b`

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "c"
	contains(content, "try_to_lock")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "try_to_lock")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_try_to_lock_re, _strip(line), 1)
	count(m) > 0
	lk := m[0][1]
	not _ownership_tested(lines, i, lk)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is constructed with std::try_to_lock but whether it owns the mutex is never checked: the code below runs whether or not the lock was acquired. Test %s.owns_lock() (or if (%s)) before touching the shared state", [lk, lk, lk]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_ownership_tested(lines, i, lk) if {
	w := helpers.code_window(lines, i, 0, 10)
	regex.match(concat("", [`\b`, lk, `\s*\.\s*owns_lock\s*\(|\b(?:if|while)\s*\(\s*!?\s*`, lk, `\s*\)|\bbool\s*\(\s*`, lk, `\s*\)|[!?]\s*`, lk, `\b|\b`, lk, `\s*\?|return\s+`, lk, `\b`]), w)
}
