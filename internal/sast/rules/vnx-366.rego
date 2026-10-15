# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_366

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-366",
	"name": "Race Condition within a Thread",
	"description": "Mutable state shared by every thread is written without synchronisation, in Java. Two shapes are reported. First, a request handler of a shared singleton writes an instance field: a servlet (a class extending HttpServlet or GenericServlet) assigning, incrementing or compound-assigning a non-static, non-final field (also through this.) inside doGet/doPost/doPut/doDelete/doPatch/doHead/service, or a Spring @Controller/@RestController doing the same inside a method annotated @GetMapping/@PostMapping/@PutMapping/@DeleteMapping/@PatchMapping/@RequestMapping. One instance serves all concurrent requests, so one user's value leaks into another's response. Second, in a file that runs on several threads (implements Runnable, extends Thread, new Thread, an ExecutorService, submit, CompletableFuture, parallelStream, ForkJoinPool, or a servlet or Spring controller), a static, non-final, non-volatile numeric field is incremented, decremented or compound-assigned (++, --, +=) outside any synchronized method or block and without a Lock, so concurrent updates are lost. Fields are the members at the class body's own indentation; a mapping annotation may wrap over several lines and be followed by other annotations. Not reported: locals (also for/catch/try-with-resources variables), handler parameters that shadow a field unless written through this., annotation arguments on parameters, final, volatile and Atomic* fields, writes in init()/constructors, plain assignments to static fields, updates inside synchronized code, files that start no threads, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-366/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [366],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["race-in-thread", "concurrency", "cwe-366"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# A class member declaration: one indentation level, a type, a name, an
# optional initialiser.
_field_re := `^(?: {2,4}|\t)((?:(?:private|protected|public|static|final|transient|volatile)\s+)*)([A-Za-z_][\w\.]*(?:<[^;=]*>)?(?:\[\])*)\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?;\s*(?://.*)?$`

_not_types := {"return", "throw", "new", "break", "continue", "package", "import", "else", "case", "assert", "yield"}

# The indentation of the top-level class's members: the first code line after
# the class declaration. A local inside a method of a two-space-indented file
# sits at four spaces and is not a field.
_member_indent(lines) := ind if {
	cs := [k | some k, l in lines; regex.match(`^(?:(?:public|final|abstract)\s+)*(?:class|enum|record)\s`, l)]
	count(cs) > 0
	ms := [k |
		some k in numbers.range(cs[0] + 1, min([count(lines) - 1, cs[0] + 40]))
		t := trim_space(lines[k])
		t != ""
		not startswith(t, "//")
		not startswith(t, "*")
		not startswith(t, "/*")
	]
	count(ms) > 0
	ind := _indent(lines[ms[0]])
}

_member_indent(lines) := -1 if {
	not regex.match(`(?m)^(?:(?:public|final|abstract)\s+)*(?:class|enum|record)\s`, concat("\n", lines))
}

_member_line(_, -1) := true

_member_line(l, ind) if {
	ind >= 0
	_indent(l) == ind
}

_fields(lines) := [[m[1], m[2], m[3]] |
	ind := _member_indent(lines)
	some l in lines
	_member_line(l, ind)
	endswith(trim_right(regex.replace(l, `//.*$`, ""), " \t"), ";")
	some m in regex.find_all_string_submatch_n(_field_re, l, 1)
	not m[2] in _not_types
	not contains(m[2], "Atomic")
]

_instance_fields(lines) := {f[2] |
	some f in _fields(lines)
	not regex.match(`\b(?:static|final|volatile)\b`, f[0])
}

_static_counters(lines) := {f[2] |
	some f in _fields(lines)
	regex.match(`\bstatic\b`, f[0])
	not regex.match(`\b(?:final|volatile)\b`, f[0])
	f[1] in {"int", "long", "short", "byte", "double", "float", "Integer", "Long", "Double"}
}

_method_re := `^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default)\s+)*[\w<>\[\],\.\s]+?\s+([A-Za-z_]\w*)\s*\([^;]*$`

_servlet_methods := {"doGet", "doPost", "doPut", "doDelete", "doPatch", "doHead", "service"}

# The request handler methods of the file and their bodies [start, end].
_handler_bodies(lines, servlet) := [[bs, e, d] |
	some d, l in lines
	contains(l, "(")
	not contains(l, ";")
	not startswith(trim_left(l, " \t"), "@")
	m := regex.find_all_string_submatch_n(_method_re, l, 1)
	count(m) > 0
	_is_handler(lines, d, m[0][1], servlet)
	e := _close(lines, d)
	bs := _body_open(lines, d, e)
]

# The line that opens the method body, after any wrapped parameter list (an
# annotation argument such as value = "x" on a parameter is not a write).
_body_open(lines, d, e) := b if {
	os := [k | some k in numbers.range(d, e); contains(regex.replace(lines[k], `"(?:[^"\\]|\\.)*"`, ""), "{")]
	count(os) > 0
	b := os[0]
}

_is_handler(_, _, name, true) if name in _servlet_methods

# The mapping annotation may wrap over several lines and be followed by other
# annotations; it belongs to this method when no member ends between them.
_is_handler(lines, d, _, false) if {
	some k in numbers.range(max([0, d - 8]), d)
	regex.match(`@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b`, lines[k])
	not _member_end_between(lines, k, d)
}

_member_end_between(lines, k, d) if {
	some x in numbers.range(k + 1, d - 1)
	t := trim_space(regex.replace(lines[x], `//.*$`, ""))
	regex.match(`[;}]$|^}`, t)
}

_close(lines, d) := e if {
	ind := _indent(lines[d])
	ends := [k |
		some k in numbers.range(d + 1, min([count(lines) - 1, d + 300]))
		_indent(lines[k]) == ind
		startswith(trim_left(lines[k], " \t"), "}")
	]
	count(ends) > 0
	e := ends[0]
}

_assign_re(f) := concat("", [`(?:^|[^\w\.])(?:this\.)?`, f, `\s*(?:=[^=]|\+\+|--|[-+*/%|&^]=)|(?:\+\+|--)(?:this\.)?`, f, `\b`])

_rmw_re(f) := concat("", [`(?:^|[^\w\.])(?:[A-Z]\w*\.)?`, f, `\s*(?:\+\+|--|[-+*/%|&^]=)|(?:\+\+|--)(?:[A-Z]\w*\.)?`, f, `\b`])

_local_decl(line, f) if regex.match(concat("", [`^\s*(?:final\s+)?[A-Za-z_][\w\.]*(?:<[^=]*>)?(?:\[\])*\s+`, f, `\s*(?:=|;)`]), line)

# A for, for-each, try-with-resources or catch variable declared in parentheses.
_local_decl(line, f) if regex.match(concat("", [`\(\s*(?:final\s+)?[A-Za-z_][\w\.]*(?:<[^=()]*>)?(?:\[\])*\s+`, f, `\s*[=:;)]`]), line)

# A parameter of the handler (its signature may wrap onto two more lines).
_param(lines, s, f) if {
	some k in numbers.range(s, min([count(lines) - 1, s + 2]))
	regex.match(concat("", [`[(,]\s*(?:final\s+)?(?:@\w+(?:\([^)]*\))?\s+)*[A-Za-z_][\w\.]*(?:<[^()]*>)?(?:\[\])*\s+`, f, `\s*[,)]`]), lines[k])
}

_shared_handler(content) := true if regex.match(`extends\s+(?:Http|Generic)Servlet\b`, content)

_shared_handler(content) := false if {
	not regex.match(`extends\s+(?:Http|Generic)Servlet\b`, content)
	regex.match(`@(?:Rest)?Controller\b`, content)
}

# Shape 1: a singleton's request handler writes an instance field.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	servlet := _shared_handler(content)
	lines := split(content, "\n")
	fs := _instance_fields(lines)
	count(fs) > 0
	some b in _handler_bodies(lines, servlet)
	some i in numbers.range(b[0] + 1, b[1] - 1)
	line := lines[i]
	not helpers.is_comment_line(line)
	some f in fs
	contains(line, f)
	regex.match(_assign_re(f), line)
	not _local_decl(line, f)
	not _local_in(lines, b[0], i, f)
	not _param_unqualified(lines, b[2], line, f)
	finding := _finding(path, i, line, sprintf("Request handler writes instance field '%s' of a %s, which one instance shares across all concurrent requests. Keep per-request data in local variables or the request/session", [f, _kind(servlet)]))
}

# A parameter shadows the field unless the write goes through this.
_param_unqualified(lines, s, line, f) if {
	_param(lines, s, f)
	not contains(line, concat("", ["this.", f]))
}

_kind(true) := "servlet"

_kind(false) := "Spring controller"

_local_in(lines, s, i, f) if {
	some k in numbers.range(s, i - 1)
	_local_decl(lines[k], f)
}

_thread_re := `implements\s+(?:[\w\.]+\s*,\s*)*Runnable\b|extends\s+Thread\b|new\s+Thread\(|ExecutorService|Executors\.|\.submit\(|CompletableFuture|parallelStream\(\)|ForkJoinPool|@(?:Rest)?Controller\b|extends\s+(?:Http|Generic)Servlet\b`

# Shape 2: a static counter updated without synchronisation in threaded code.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_thread_re, content)
	contains(content, "static")
	lines := split(content, "\n")
	cs := _static_counters(lines)
	count(cs) > 0
	some i, line in lines
	regex.match(`\+\+|--|[-+*/%|&^]=`, line)
	not helpers.is_comment_line(line)
	some f in cs
	contains(line, f)
	regex.match(_rmw_re(f), line)
	ms := _method_start(lines, i)
	not _synchronised(lines, ms, i)
	finding := _finding(path, i, line, sprintf("Static field '%s' is updated with a read-modify-write outside synchronized code in a class that runs on several threads; updates are lost. Use an AtomicInteger/AtomicLong/LongAdder or synchronise the update", [f]))
}

# The nearest enclosing method declaration at class-member indentation.
_method_start(lines, i) := ms if {
	cands := [k |
		some k in numbers.range(max([0, i - 80]), i - 1)
		_indent(lines[k]) <= 4
		_indent(lines[k]) > 0
		contains(lines[k], "(")
		regex.match(_method_re, lines[k])
	]
	count(cands) > 0
	ms := max(cands)
}

_synchronised(lines, ms, i) if {
	some k in numbers.range(ms, i)
	regex.match(`\bsynchronized\b|\.(?:lock|writeLock|acquire)\(\)`, lines[k])
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
