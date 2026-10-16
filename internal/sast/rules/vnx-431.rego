# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_431

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-431",
	"name": "Missing Handler",
	"description": "An error that the code or its container is expected to handle has no handler, in Java. Reported: a deployment descriptor (WEB-INF/web.xml) whose <web-app> declares no <error-page> for uncaught exceptions (none with <exception-type> java.lang.Throwable, Exception or RuntimeException, none with <error-code>500</error-code>, and no default <error-page> with only a <location>; an error page inside an XML comment does not count), so an exception reaches the servlet container's default error page with its stack trace and server version; a CompletableFuture.runAsync/supplyAsync (or a statically imported runAsync/supplyAsync) whose future is discarded (the statement is not assigned, returned or passed on) and whose chain carries no exceptionally/handle/whenComplete/join/get on the future itself (a get() inside the task, such as map.get(k), is not a handler), so an exception thrown by the task is lost with no handler ever seeing it; and ExecutorService.submit (on a variable declared as an ExecutorService, ScheduledExecutorService, Guava ListeningExecutorService, ThreadPoolExecutor, ForkJoinPool or a Spring ThreadPoolTaskExecutor/ThreadPoolTaskScheduler/AsyncTaskExecutor, or assigned from Executors.*) whose Future is discarded, which swallows the task's exception the same way (execute() would reach the uncaught-exception handler). Not reported: a task whose body catches Exception or Throwable itself, a kept future, execute(), test sources, web.xml files under test directories, comments. A broad @ExceptionHandler(Exception.class) is a handler, not a missing one, and is not reported. The rule is evaluated only when the scanned tree also contains Java source, so a web.xml scanned alone, with no .java file beside it, is not read.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-431/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [431],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-handler", "error-handling", "cwe-431"],
}

# ── web.xml with no error page for uncaught exceptions ───────────────────

_error_page_covered(content) if regex.match(`(?s)<error-page>\s*(?:<!--.*?-->\s*)*(?:<exception-type>\s*java\.lang\.(?:Throwable|Exception|RuntimeException)\s*</exception-type>|<error-code>\s*500\s*</error-code>|<location>)`, content)

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(^|/)web\.xml$`, path)
	not helpers.is_test_path(path)
	contains(content, "<web-app")
	not _error_page_covered(regex.replace(content, `(?s)<!--.*?-->`, ""))
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "<web-app")
	regex.match(`^\s*<web-app(?:[\s>]|$)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "The web application declares no error page for uncaught exceptions: an exception reaches the container's default error page, which shows the stack trace and server version. Add <error-page><exception-type>java.lang.Throwable</exception-type><location>/error</location></error-page>",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Discarded futures in Java ────────────────────────────────────────────

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The statement that starts at line i: following lines that are indented
# deeper, or that continue the chain at the same indent (.then(), }).x(), ).
_stmt(lines, i) := s if {
	base := _indent(lines[i])
	last := min([count(lines) - 1, i + 30])
	ends := [j |
		some j in numbers.range(i + 1, last)
		l := lines[j]
		trim_space(l) != ""
		_ends_stmt(l, base)
	]
	end := _first_or(ends, last + 1)
	s := concat("\n", [lines[k] | some k in numbers.range(i, end - 1)])
}

_first_or(xs, _) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

_ends_stmt(l, base) if _indent(l) < base

_ends_stmt(l, base) if {
	_indent(l) == base
	not regex.match(`^\s*[.})\]]`, l)
}

_handler_calls := [
	".exceptionally(", ".exceptionallyAsync(", ".exceptionallyCompose(", ".handle(", ".handleAsync(",
	".whenComplete(", ".whenCompleteAsync(", ".join(", ".get(",
]

# A handler counts only on the future itself: at parenthesis depth zero from
# the start of the statement, so map.get(k) inside the task is not a handler.
_handled(s) if {
	some h in _handler_calls
	contains(s, h)
	some idx in indexof_n(s, h)
	p := substring(s, 0, idx)
	count(split(p, "(")) == count(split(p, ")"))
}

_handled(s) if regex.match(`catch\s*\(\s*(?:final\s+)?(?:[\w.]+\s*\|\s*)*(?:java\.lang\.)?(?:Exception|Throwable|RuntimeException)\b`, s)

_executor_var(content, v) if regex.match(concat("", [`\b(?:ExecutorService|ScheduledExecutorService|ListeningExecutorService|ThreadPoolExecutor|ScheduledThreadPoolExecutor|ForkJoinPool|ThreadPoolTaskExecutor|ThreadPoolTaskScheduler|AsyncTaskExecutor|AsyncListenableTaskExecutor)\s+`, v, `\s*[=;,)]`]), content)

_executor_var(content, v) if regex.match(concat("", [`\b`, v, `\s*=\s*(?:Executors\s*\.\s*new\w+|new\s+(?:ThreadPoolExecutor|ScheduledThreadPoolExecutor|ForkJoinPool)\b|ForkJoinPool\.commonPool\(\))`]), content)

_reason(lines, i, content) := "CompletableFuture task started and its future discarded with no exceptionally/handle/whenComplete: an exception thrown by the task is silently lost. Keep the future and attach a handler, or catch inside the task" if {
	_async_start(lines[i], content)
	not _handled(_stmt(lines, i))
}

_async_start(line, _) if regex.match(`^\s*CompletableFuture\s*\.\s*(?:runAsync|supplyAsync)\s*\(`, line)

# runAsync(...) through a static import.
_async_start(line, content) if {
	regex.match(`^\s*(?:runAsync|supplyAsync)\s*\(`, line)
	regex.match(`(?m)^\s*import\s+static\s+java\.util\.concurrent\.CompletableFuture\.(?:runAsync|supplyAsync|\*)\s*;`, content)
}

_reason(lines, i, content) := "ExecutorService.submit() result discarded: the Future holds any exception the task throws, so it is silently lost. Keep the Future and check it, catch inside the task, or use execute() so the uncaught-exception handler sees it" if {
	m := regex.find_all_string_submatch_n(`^\s*(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*\.\s*submit\s*\(`, lines[i], 1)
	count(m) > 0
	_executor_var(content, m[0][1])
	not _handled(_stmt(lines, i))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`CompletableFuture\s*\.\s*(?:runAsync|supplyAsync|\*)|\.\s*submit\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:runAsync|supplyAsync|submit)\s*\(`, line)
	not helpers.is_comment_line(line)
	msg := _reason(lines, i, content)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
