# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_911

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-911",
	"name": "Improper Update of Reference Count",
	"description": "A reference count is not updated, or not updated safely. Reported: (1) Java/Netty: a channelRead(ChannelHandlerContext, Object msg) override that consumes the message without releasing it or passing it on (no ReferenceCountUtil.release/safeRelease, msg.release()/retain() on the message or the ByteBuf cast from it, super.channelRead, out.add, or a call that takes the message or that ByteBuf, such as ctx.fireChannelRead(msg) or outbound.writeAndFlush(in); writing a different buffer back as a reply, or passing the message to a logging call, consumes nothing), so the pooled buffer's count never reaches zero and it leaks; (2) Java: a primitive int/long field named as a reference count (refCount, refCnt, referenceCount, useCount, retainCount ...) changed with ++, --, += or -= in a method that is not synchronized, outside a synchronized block and without a lock() above it in the method, so two threads lose an update and the object is freed while in use or never freed (volatile does not make ++ atomic); (3) CPython C extensions: return Py_None/Py_True/Py_False/Py_NotImplemented/Py_Ellipsis without Py_INCREF of it on the lines above (use Py_RETURN_NONE or Py_NewRef), and Py_DECREF/Py_XDECREF/Py_CLEAR of a borrowed reference (from PyList_GetItem, PyTuple_GetItem, PyDict_GetItem/GetItemString/GetItemWithError, PySequence_Fast_GET_ITEM, PyModule_GetDict, PySys_GetObject ...) within 30 lines with no Py_INCREF/Py_NewRef of it or reassignment between, which frees an object the container still owns; the same for an object stored through &obj by PyArg_ParseTuple/ParseTupleAndKeywords/UnpackTuple (borrowed from the argument tuple; formats with an O& converter are skipped). Not reported: SimpleChannelInboundHandler.channelRead0 (released by Netty), Atomic* counters, synchronized or locked updates, constructors' plain assignments, new references (PyObject_Str, PyObject_GetAttrString ...) released with Py_DECREF, test sources, comments and strings. Counts managed through helper methods or across files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-911/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [911],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["reference-count", "cwe-911", "netty", "cpython", "race-condition"],
}

_rng(a, b) := numbers.range(a, b) if a <= b

_rng(a, b) := [] if a > b

_indent(line) := count(line) - count(trim_left(line, " \t"))

# String literals and trailing comments removed.
_code(line) := regex.replace(regex.replace(line, `"(?:\\.|[^"\\])*"`, `""`), `/\*.*?\*/|//.*$`, "")

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# The body of the block opened by the declaration at i: lines after it up to
# the closing brace at the declaration's indent (60 lines max).
_block_end(lines, i) := e if {
	d := _indent(lines[i])
	hi := min([count(lines) - 1, i + 60])
	ends := [k |
		some k in _rng(i + 1, hi)
		_indent(lines[k]) == d
		startswith(trim_left(lines[k], " \t"), "}")
	]
	e := min(array.concat([hi], ends))
}

# ── (1) Netty channelRead that neither releases nor forwards ─────────────

_channel_read := `\bvoid\s+channelRead\s*\(\s*(?:final\s+)?ChannelHandlerContext\s+\w+\s*,\s*(?:final\s+)?Object\s+(\w+)\s*\)`

_hands_off := `ReferenceCountUtil\.(?:release|safeRelease|retain|touch)\s*\(|super\.channelRead\s*\(|\bout\.add\s*\(`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "channelRead")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "channelRead")
	m := regex.find_all_string_submatch_n(_channel_read, concat(" ", array.slice(lines, i, i + 3)), 1)
	count(m) > 0
	regex.match(`\bvoid\s+channelRead\s*\(`, line)
	msg := m[0][1]
	e := _block_end(lines, i)
	body := concat("\n", [_code(lines[k]) | some k in _rng(i + 1, e)])
	not regex.match(_hands_off, body)
	not _passed_on(body, msg)
	f := _finding(path, i, line, "channelRead consumes the message without releasing it or passing it on: a reference-counted ByteBuf's count never reaches zero and the pooled buffer leaks. Release it in a finally block (ReferenceCountUtil.release(msg)), forward it with ctx.fireChannelRead(msg), or extend SimpleChannelInboundHandler")
}

# The message, or a variable cast from it, is released, retained, or handed
# to another call (ctx.fireChannelRead(msg), outbound.writeAndFlush(in)).
# A logging or printing call that takes it consumes nothing, and a write of a
# different buffer (a reply) does not release the one that arrived.
_passed_on(body, msg) if {
	some v in _aliases(body, msg)
	regex.match(concat("", [`\b`, v, `\.(?:release|retain\w*)\s*\(`]), body)
}

_passed_on(body, msg) if {
	some v in _aliases(body, msg)
	some cm in regex.find_all_string_submatch_n(concat("", [`(\w+)\s*\((?:[^()]*,)?\s*(?:\(\s*\w+\s*\)\s*)?`, v, `\s*[,)]`]), body, -1)
	not _log_call[cm[1]]
}

_log_call := {"trace", "debug", "info", "warn", "warning", "error", "fatal", "log", "println", "print", "printf", "format", "valueOf", "toString", "hexDump", "prettyHexDump", "requireNonNull"}

_aliases(body, msg) := {msg} | {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`\b(\w+)\s*=\s*\(\s*\w+\s*\)\s*`, msg, `\b`]), body, -1)
}

# ── (2) Reference-count field updated without synchronization ────────────

_count_name := `[A-Za-z_]\w*(?:[Rr]ef_?[Cc](?:ou)?n?t|[Rr]eference_?[Cc]ount|[Uu]se_?[Cc]ount|[Uu]sage_?[Cc]ount|[Rr]etain_?[Cc]ount)\w*|ref_?c(?:ou)?n?t\w*|refCount|refCnt|referenceCount|useCount|usageCount|retainCount`

_count_field := concat("", [`(?m)^\s*(?:(?:private|protected|public|static|volatile|transient)\s+)*(?:int|long|short)\s+(`, _count_name, `)\s*(?:=[^;]*)?;`])

_method_header := `^\s*(?:@\w+\s+)*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*(?:<[^>]+>\s+)?[\w<>\[\],.? ]+\s+\w+\s*\([^;]*$|^\s*(?:public|private|protected)\s+[A-Z]\w*\s*\([^;]*$`

_update_re(name) := concat("", [`(?:^|[^\w.]|this\.)`, name, `\s*(?:\+\+|--|[+-]=)|(?:\+\+|--)\s*(?:this\.)?`, name, `\b`])

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	some fm in regex.find_all_string_submatch_n(_count_field, content, -1)
	name := fm[1]
	lines := split(content, "\n")
	some i, line in lines
	contains(line, name)
	not helpers.is_comment_line(line)
	regex.match(_update_re(name), _code(line))
	h := _header(lines, i)
	not _guarded(lines, h, i)
	f := _finding(path, i, line, sprintf("The reference count '%s' is changed with a plain ++/--/+= outside any synchronized method, synchronized block or lock: two threads can read the same value and one update is lost, so the object is freed while still referenced or never freed. Use an AtomicInteger/AtomicLong (or AtomicIntegerFieldUpdater) or update it under a lock", [name]))
}

# The method enclosing line i.
_header(lines, i) := h if {
	hs := [k |
		some k in _rng(max([0, i - 80]), i - 1)
		regex.match(_method_header, lines[k])
		not regex.match(`^\s*(?:if|for|while|switch|catch|return|else|new|throw)\b`, lines[k])
	]
	count(hs) > 0
	h := hs[count(hs) - 1]
}

_guarded(lines, h, _) if regex.match(`\bsynchronized\b`, lines[h])

_guarded(lines, h, i) if {
	some k in _rng(h + 1, i - 1)
	regex.match(`\bsynchronized\s*\(|\.(?:lock|lockInterruptibly|tryLock|writeLock\(\)\.lock|acquire)\s*\(`, lines[k])
	not helpers.is_comment_line(lines[k])
}

# A constructor, which runs before the object is shared.
_guarded(lines, h, _) if regex.match(`^\s*(?:public|private|protected)?\s*[A-Z]\w*\s*\(`, lines[h])

# ── (3) CPython reference counting ───────────────────────────────────────

_c_family(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".c++", ".h"}
	endswith(path, ext)
}

_singleton_return := `^\s*return\s+(Py_None|Py_True|Py_False|Py_NotImplemented|Py_Ellipsis)\s*;`

findings contains f if {
	some path, content in input.file_contents
	_c_family(path)
	contains(content, "Py_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "return Py_")
	m := regex.find_all_string_submatch_n(_singleton_return, line, 1)
	count(m) > 0
	obj := m[0][1]
	not _increfed_above(lines, i, obj)
	f := _finding(path, i, line, sprintf("%s is returned without Py_INCREF: the caller receives a new reference it will Py_DECREF, so the singleton's count drops below the number of real references and the interpreter eventually deallocates it. Use Py_RETURN_NONE/Py_RETURN_TRUE/Py_RETURN_FALSE or return Py_NewRef(%s)", [obj, obj]))
}

_increfed_above(lines, i, obj) if {
	some k in _rng(max([0, i - 3]), i - 1)
	contains(lines[k], obj)
	regex.match(`Py_X?INCREF\s*\(|Py_X?NewRef\s*\(`, lines[k])
}

_borrowed := `\b([A-Za-z_]\w*)\s*=\s*(?:\(\s*PyObject\s*\*\s*\)\s*)?(?:PyList_GetItem|PyList_GET_ITEM|PyTuple_GetItem|PyTuple_GET_ITEM|PyDict_GetItem|PyDict_GetItemString|PyDict_GetItemWithError|PySequence_Fast_GET_ITEM|PyModule_GetDict|PyEval_GetBuiltins|PyEval_GetGlobals|PyEval_GetLocals|PySys_GetObject|PyWeakref_GetObject|PyCell_GET|PyFunction_GetCode|PyFunction_GetGlobals|PyImport_GetModuleDict|PyErr_Occurred)\s*\(`

_decref := `\bPy_(?:X?DECREF|CLEAR|SETREF)\s*\(\s*([A-Za-z_]\w*)\s*[,)]`

findings contains f if {
	some path, content in input.file_contents
	_c_family(path)
	contains(content, "DECREF")
	regex.match(`(?:GetItem|GET_ITEM|GetDict|GetObject|GetBuiltins|GetGlobals|GetLocals|GetCode|CELL_GET|_GET\()`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Py")
	bm := regex.find_all_string_submatch_n(_borrowed, line, 1)
	count(bm) > 0
	v := bm[0][1]
	some u in _rng(i + 1, min([count(lines) - 1, i + 30]))
	contains(lines[u], v)
	dm := regex.find_all_string_submatch_n(_decref, lines[u], 1)
	count(dm) > 0
	dm[0][1] == v
	not _owned_between(lines, i, u, v)
	f := _finding(path, u, lines[u], sprintf("'%s' holds a borrowed reference (the container still owns it), yet it is released here: the object's count drops while the container still points at it, a use-after-free. Py_INCREF it first if you need your own reference, or do not release it", [v]))
}

# Between the borrow and the release, the variable took its own reference,
# was reassigned, or the function ended.
_owned_between(lines, i, u, v) if {
	some k in _rng(i + 1, u - 1)
	_owns(lines[k], v)
}

_owns(l, _) if startswith(l, "}")

_owns(l, v) if {
	contains(l, v)
	some m in regex.find_all_string_submatch_n(`Py_X?INCREF\s*\(\s*([A-Za-z_]\w*)\s*\)|Py_X?NewRef\s*\(\s*([A-Za-z_]\w*)\s*\)|\b([A-Za-z_]\w*)\s*=[^=]`, l, -1)
	some x in array.slice(m, 1, count(m))
	x == v
}

# Objects PyArg_ParseTuple/ParseTupleAndKeywords/UnpackTuple store through
# &obj are borrowed from the argument tuple; a format with an O& converter is
# skipped, since a converter may hand back a new reference.
findings contains f if {
	some path, content in input.file_contents
	_c_family(path)
	contains(content, "DECREF")
	contains(content, "PyArg_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "PyArg_")
	joined := concat(" ", array.slice(lines, i, i + 4))
	am := regex.find_all_string_submatch_n(`PyArg_(?:ParseTuple|ParseTupleAndKeywords|UnpackTuple)\s*\(((?:[^()]|\([^()]*\))*)\)`, joined, 1)
	count(am) > 0
	not contains(am[0][1], "O&")
	some vm in regex.find_all_string_submatch_n(`&\s*([A-Za-z_]\w*)`, _code(am[0][1]), -1)
	v := vm[1]
	some u in _rng(i + 1, min([count(lines) - 1, i + 30]))
	contains(lines[u], v)
	dm := regex.find_all_string_submatch_n(_decref, lines[u], 1)
	count(dm) > 0
	dm[0][1] == v
	not _owned_between(lines, i, u, v)
	f := _finding(path, u, lines[u], sprintf("'%s' was filled by PyArg_ParseTuple, which stores a borrowed reference (the argument tuple owns it), yet it is released here: the caller's object loses a reference it still holds, a use-after-free. Py_INCREF it first if you keep it, or do not release it", [v]))
}
