# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1058

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1058",
	"name": "Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element",
	"description": "A Java class that runs on several threads at once declares a static field that is neither final nor volatile and of a type that is not thread-safe, and a method of the class writes it without holding a lock (CWE-1058): an assignment, a compound assignment or increment, or a mutating call (put, add, remove, clear, append, ...) on the field, outside its declaration, any static initialiser and main(), while the enclosing method is not synchronized and no synchronized block or Lock.lock() opens between that method's header and the write (a synchronized sibling method does not protect it). A static SimpleDateFormat/DateFormat/NumberFormat/MessageFormat/Calendar field also counts when it is only used (format, parse, setTime), because those calls mutate it. The finding is on the field's declaration. A class counts as multi-threaded when it is a request-handling or managed singleton (extends HttpServlet/GenericServlet, implements Filter, is annotated @Controller/@RestController/@Service/@Component/@Repository/@Endpoint/@Path, or extends an Android ContentProvider) or starts concurrent work itself (implements Runnable/Callable, extends Thread, uses an ExecutorService, new Thread, CompletableFuture, parallelStream, @Async or @Scheduled). Not reported: static final constants, volatile fields, Atomic*/LongAdder/Concurrent*/CopyOnWrite*/ThreadLocal/Collections.synchronized* fields, static fields that are only read or only set in a static initialiser, classes with no concurrency signal, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1058/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1058],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["multi-thread-non-final-static", "concurrency", "race-condition", "cwe-1058"],
}

_concurrent_re := `\bextends\s+(?:Http|Generic)Servlet\b|\bimplements\s+[\w\s,<>.]*\b(?:Filter|Runnable|Callable)\b|\bextends\s+(?:Thread|ContentProvider)\b|(?m)^\s*@(?:Controller|RestController|Service|Component|Repository|Endpoint|Path|WebServlet|WebFilter|Async|Scheduled)\b|\bExecutorService\b|\bExecutors\.|\bnew\s+Thread\s*\(|\bCompletableFuture\b|\.parallelStream\s*\(`

_decl_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|transient)\s+)*static\s+(?:(?:public|private|protected|transient)\s+)*([A-Za-z_][\w.]*(?:\s*<[^;=()]*>)?(?:\s*\[\s*\])*)\s+([A-Za-z_]\w*)\s*(?:=|;)`

_safe_type_re := `^(?:Atomic\w*|LongAdder|DoubleAdder|LongAccumulator|Concurrent\w*|CopyOnWrite\w*|ThreadLocal|InheritableThreadLocal|Logger|Log|Semaphore|CountDownLatch|ReentrantLock|ReentrantReadWriteLock|StampedLock|Lock|ReadWriteLock|BlockingQueue|\w*BlockingQueue|\w*BlockingDeque)(?:\s*<.*)?$|(?:^|\.)(?:Atomic\w*|Concurrent\w*|ThreadLocal)(?:\s*<.*)?$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Static initialiser blocks: [start, end] line ranges.
_static_blocks(lines) := {[s, e] |
	some s, l in lines
	regex.match(`^\s*static\s*\{`, l)
	k := _indent(l)
	last := min([count(lines) - 1, s + 200])
	ends := [j |
		some j in numbers.range(s + 1, last)
		_indent(lines[j]) <= k
		startswith(trim_space(lines[j]), "}")
	]
	e := min(array.concat([last], ends))
}

_in_block(blocks, j) if {
	some b in blocks
	j >= b[0]
	j <= b[1]
}

_write_re(name) := concat("", [
	`(?:^|[^.\w])(?:this\.|[A-Z]\w*\.)?`, name, `\s*(?:=[^=]|\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=|\+\+|--)`,
	`|(?:\+\+|--)\s*(?:[A-Z]\w*\.)?`, name, `\b`,
	`|(?:^|[^.\w])(?:this\.|[A-Z]\w*\.)?`, name, `\s*\.\s*(?:put|putAll|putIfAbsent|add|addAll|remove|removeAll|removeIf|clear|set|push|pop|offer|poll|append|insert|merge|compute|computeIfAbsent|computeIfPresent|replace|replaceAll|setLength|delete|deleteCharAt|sort)\s*\(`,
])

# A local variable of the same name declared on the line (int count = 0).
_local_decl(line, name) if regex.match(concat("", [`^\s*(?:final\s+)?[A-Za-z_][\w.<>\[\],?\s]*[\w>\]]\s+`, name, `\s*[=;:]`]), line)

# Formatter and calendar types keep mutable state that every format/parse call
# changes, so a shared instance races even when the field is only "read".
_unsafe_fmt_type := `^(?:java\.text\.|java\.util\.)?(?:SimpleDateFormat|DateFormat|DecimalFormat|NumberFormat|MessageFormat|Calendar|GregorianCalendar)$`

_use_re(name) := concat("", [`(?:^|[^.\w])(?:[A-Z]\w*\.)?`, name, `\s*\.\s*(?:format|parse|parseObject|setTime|setTimeInMillis|setTimeZone|add|roll|applyPattern)\s*\(`])

_method_header_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|static|final|synchronized|native|abstract|default)\s+)*[A-Za-z_][\w<>\[\]?,. ]*?\s+([a-zA-Z_]\w*)\s*\([^;=]*$`

# The declaration of the method that encloses line j: the nearest method
# header in the 60 lines above.
_method_start(lines, j) := max(starts) if {
	starts := [k |
		some k in numbers.range(max([0, j - 60]), j)
		contains(lines[k], "(")
		m := regex.find_all_string_submatch_n(_method_header_re, lines[k], 1)
		count(m) > 0
		not regex.match(`^(?:if|for|while|switch|catch|synchronized|return|new|throw|else)$`, m[0][1])
		not regex.match(`^\s*(?:return|new|throw|else)\b`, lines[k])
	]
	count(starts) > 0
}

_lock_re := `\bsynchronized\b|\.(?:lock|writeLock\(\)\.lock|tryLock)\s*\(`

# Held lock: the enclosing method is synchronized, or a synchronized block or
# Lock.lock() opens between its header and the write.
_guarded(lines, j) if {
	k := _method_start(lines, j)
	some n in numbers.range(k, j)
	regex.match(_lock_re, lines[n])
	not helpers.is_comment_line(lines[n])
}

# No recognisable method header: fall back to the 25 lines above.
_guarded(lines, j) if {
	not _method_start(lines, j)
	some n in numbers.range(max([0, j - 25]), j)
	regex.match(_lock_re, lines[n])
	not helpers.is_comment_line(lines[n])
}

# main() runs on the starting thread before any worker exists.
_in_main(lines, j) if {
	k := _method_start(lines, j)
	regex.match(`\bstatic\s+void\s+main\s*\(`, lines[k])
}

_writes(lines, d, name, typ, blocks) := [j |
	re := _access_re(name, typ)
	some j, l in lines
	j != d
	contains(l, name)
	regex.match(re, l)
	not helpers.is_comment_line(l)
	not _local_decl(l, name)
	not _in_block(blocks, j)
	not _guarded(lines, j)
	not _in_main(lines, j)
]

_access_re(name, typ) := concat("|", [_write_re(name), _use_re(name)]) if regex.match(_unsafe_fmt_type, typ)

else := _write_re(name)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "static ")
	regex.match(_concurrent_re, content)
	regex.match(`(?m)^\s*(?:@\w+\s+)*(?:(?:public|private|protected|transient)\s+)*static\s+[A-Za-z_]`, content)
	lines := split(content, "\n")
	blocks := _static_blocks(lines)
	some d, line in lines
	contains(line, "static ")
	not regex.match(`\b(?:final|volatile)\b`, line)
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)
	count(m) > 0
	typ := m[0][1]
	name := m[0][2]
	not regex.match(`^(?:class|interface|enum|record|void|abstract|native|synchronized)$`, typ)
	not regex.match(_safe_type_re, typ)
	not regex.match(`=\s*Collections\.synchronized`, line)
	ws := _writes(lines, d, name, typ, blocks)
	count(ws) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Static field %s is not final and is written or mutated without a lock (line %d) in a class that runs on several threads; make it final and immutable, an instance field, an Atomic/concurrent type, or guard every access (CWE-1058)", [name, ws[0] + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d + 1,
		"snippet": line,
	}
}
