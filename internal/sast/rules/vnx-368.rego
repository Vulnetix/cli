# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_368

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-368",
	"name": "Context Switching Race Condition",
	"description": "A temporary switch into the root context (seteuid(0), setegid(0), setreuid(-1, 0), setregid(-1, 0), setresuid(-1, 0, -1) or setresgid(-1, 0, -1), also ::-qualified) that is not an atomic, contained step, in C or C++. Reported when the file starts threads (pthread_create, thrd_create, std::thread, std::jthread, std::async, boost::thread, g_thread_new, CreateThread, #pragma omp parallel): the effective ID is process-wide, so every other thread runs as root for the whole switch; when the function returns or jumps out (return, goto) between the elevation and the call that switches back, leaving the process in the root context on that path; and when the function never switches back at all. Not reported: a failure exit that belongs to the elevation call itself (if (seteuid(0) != 0) return -1, or a braced failure block after it), an elevation after fork() in the same function (the single-threaded child, which ends its context when it exits; a parent branch after the fork is also skipped), an elevation that restores root after the same function lowered it, permanent drops (setuid, setgid, setresuid with three IDs), comments and string literals. The order of a permanent drop is VNX-269, and exec after a temporary drop is VNX-270.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-368/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [368],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["context-switch-race", "privilege", "cwe-368"],
}

_exts := {".c", ".cc", ".cpp", ".cxx"}

_elev_re := `(?:^|[^\w])(?:::)?(?:(set(?:e|re|res)uid)|(set(?:e|re|res)gid))\(\s*(?:0|-1\s*,\s*0|-1\s*,\s*0\s*,\s*-1)\s*\)`

_threads_re := `\bpthread_create\s*\(|\bthrd_create\s*\(|\bstd::j?thread\b|\bstd::async\s*\(|\bboost::thread\b|\bg_thread_new\s*\(|\bCreateThread\s*\(|#\s*pragma\s+omp\s+parallel`

_code(line) := regex.replace(line, `"(?:[^"\\\n]|\\.)*"`, `""`)

_family(m) := "uid" if m[1] != ""

_family(m) := "gid" if m[2] != ""

_switch_re("uid") := `\bset(?:e|re|res)?uid\s*\(`

_switch_re("gid") := `\bset(?:e|re|res)?gid\s*\(`

_fn_start(lines, i) := s if {
	cands := [k |
		some k in numbers.range(max([0, i - 200]), i)
		regex.match(`^[A-Za-z_][^;]*\(`, lines[k])
		not endswith(trim_space(lines[k]), ";")
	]
	count(cands) > 0
	s := max(cands)
}

_fn_end(lines, i) := e if {
	ends := [k | some k in numbers.range(i + 1, min([count(lines) - 1, i + 300])); startswith(lines[k], "}")]
	count(ends) > 0
	e := ends[0]
}

# Another switch of the same family after the elevation (the switch back).
_restores(lines, i, e, fam) := [k |
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	l := _code(lines[k])
	not helpers.is_comment_line(l)
	regex.match(_switch_re(fam), l)
	not regex.match(_elev_re, l)
]

# The same function lowered the ID earlier: this is the switch back to root.
_lowered_before(lines, s, i, fam) if {
	s <= i - 1
	some k in numbers.range(s, i - 1)
	l := _code(lines[k])
	not helpers.is_comment_line(l)
	regex.match(_switch_re(fam), l)
	not regex.match(_elev_re, l)
}

# The failure exit of the elevation call itself.
_own_failure_exit(lines, i, j) if {
	regex.match(`^\s*if\s*\(`, lines[i])
	j == i + 1
}

# if (seteuid(0) == -1) { perror(...); return -1; }: the braced failure block
# of the elevation call, up to its closing brace at the if's indentation.
_own_failure_exit(lines, i, j) if {
	regex.match(`^\s*if\s*\(.*\{\s*$`, lines[i])
	ind := _indent(lines[i])
	closes := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
		_indent(lines[k]) == ind
		startswith(trim_left(lines[k], " \t"), "}")
	]
	count(closes) > 0
	j < closes[0]
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The elevation runs in a child created by fork() earlier in the function:
# the child is single-threaded and its context ends when it exits.
_after_fork(lines, s, i) if {
	some k in numbers.range(s, i - 1)
	regex.match(`\bv?fork\s*\(\s*\)`, lines[k])
}

_exit_between(lines, i, k) if {
	i + 1 <= k - 1
	some j in numbers.range(i + 1, k - 1)
	regex.match(`^\s*(?:return\b|goto\s)|[;{)]\s*(?:return\b|goto\s)`, lines[j])
	not helpers.is_comment_line(lines[j])
	not _own_failure_exit(lines, i, j)
}

_reason(_, _, _, _, _, true) := "the file starts threads and the effective ID is process-wide, so every thread runs as root until the switch back"

_reason(lines, s, i, e, fam, false) := "the function never switches back, so the process stays in the root context" if {
	not _lowered_before(lines, s, i, fam)
	count(_restores(lines, i, e, fam)) == 0
}

_reason(lines, s, i, e, fam, false) := "the function can return or jump out before it switches back, leaving the process in the root context on that path" if {
	not _lowered_before(lines, s, i, fam)
	rs := _restores(lines, i, e, fam)
	count(rs) > 0
	_exit_between(lines, i, min(rs))
}

_threaded(content) := true if regex.match(_threads_re, content)

_threaded(content) := false if not regex.match(_threads_re, content)

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	contains(content, "set")
	regex.match(`set(?:e|re|res)[ug]id\s*\(`, content)
	threaded := _threaded(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "set")
	not helpers.is_comment_line(line)
	ms := regex.find_all_string_submatch_n(_elev_re, _code(line), 1)
	count(ms) > 0
	fam := _family(ms[0])
	s := _fn_start(lines, i)
	e := _fn_end(lines, i)
	not _after_fork(lines, s, i)
	why := _reason(lines, s, i, e, fam, threaded)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Temporary switch to root is not contained: %s. Do the privileged step in a separate, single-threaded helper process, or switch back on every path", [why]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
