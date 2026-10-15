# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_572

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-572",
	"name": "Call to Thread run() instead of start()",
	"description": "A java.lang.Thread whose run() method is called directly, in Java or Kotlin, so its work executes synchronously on the calling thread instead of on a new one: the caller blocks, and any isolation, timeout or concurrency the thread was meant to give is lost. Reported: new Thread(...).run() (also when the lambda body spans lines and the call closes with }).run()), Thread { ... }.run() in Kotlin, and x.run() / this.x.run() where x is declared in the same file as a Thread (a field, local, parameter, var x = new Thread(...), Thread.ofVirtual().unstarted(...), val x = Thread(...)) or as a class of the file that extends Thread (including a for (Thread t : ...) loop variable), and workers[i].run() on an array declared Thread[]. Not reported: start(), run() on a Runnable or any other type, super.run() inside a run() override, Kotlin's run { } scope function, and the call in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-572/",
	"languages": ["java", "kotlin"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [572],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["no-invocation", "thread", "concurrency", "cwe-572"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "kt" if endswith(path, ".kt")

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `//.*$`, "")

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Classes of this file that extend Thread.
_subclasses(content, "java") := {m[1] | some m in regex.find_all_string_submatch_n(`class\s+(\w+)\s+extends\s+Thread\b`, content, -1)}

_subclasses(content, "kt") := {m[1] | some m in regex.find_all_string_submatch_n(`class\s+(\w+)[^{\n]*:\s*Thread\s*\(`, content, -1)}

_thread_types(content, lang) := {"Thread"} | _subclasses(content, lang)

# Names declared as a Thread (or a Thread subclass) anywhere in the file.
_names(content, "java", types) := {v |
	some t in types
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, t, `\s+(\w+)\s*[=;,):]`]), content, -1)
	v := m[1]
} | {v |
	# Thread[] workers: recorded as "workers[]" for workers[i].run().
	some t in types
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, t, `\s*\[\s*\]\s*(\w+)\s*[=;,)]`]), content, -1)
	v := concat("", [m[1], "[]"])
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\bvar\s+(\w+)\s*=\s*(?:new\s+\w+|Thread\.of(?:Virtual|Platform)\(\)[\w.]*\.unstarted)\b`, content, -1)
	_var_is_thread(m[0], types)
}

_names(content, "kt", types) := {v |
	some t in types
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:val|var)\s+(\w+)\s*(?::\s*`, t, `\b[^=\n]*)?=\s*`, t, `\s*[({]`]), content, -1)
	v := m[1]
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\b(?:val|var)\s+(\w+)\s*:\s*Thread\b`, content, -1)
}

_var_is_thread(decl, _) if contains(decl, "unstarted")

_var_is_thread(decl, types) if {
	some t in types
	regex.match(concat("", [`new\s+`, t, `$`]), decl)
}

# An instance created and run in one expression.
_inline_re(types, "java") := concat("", [`\bnew\s+(?:`, concat("|", types), `)\s*\(.*\)\s*\.run\(\)`])

_inline_re(types, "kt") := concat("", [`(?:^|[^\w.])(?:`, concat("|", types), `)\s*(?:\(.*\)|\{.*\})\s*\.run\(\)`])

_open_re(types, "java") := concat("", [`\bnew\s+(?:`, concat("|", types), `)\s*\(`])

_open_re(types, "kt") := concat("", [`(?:^|[^\w.])(?:`, concat("|", types), `)\s*[({]`])

_hit(_, _, c, _, types, lang) if regex.match(_inline_re(types, lang), c)

# `}).run();` closing a constructor call opened above at the same indent.
_hit(lines, i, c, _, types, lang) if {
	regex.match(`^\s*\}\s*\)?\s*\.run\(\)`, c)
	ind := _indent(lines[i])
	opens := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		_indent(lines[j]) == ind
		trim_space(lines[j]) != ""
	]
	count(opens) > 0
	regex.match(_open_re(types, lang), _code(lines[max(opens)]))
}

# x.run() / this.x.run() on a name declared as a Thread.
_hit(_, _, c, names, _, _) if {
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.])(?:this\.)?(\w+)\.run\(\)`, c, -1)
	m[1] in names
}

# workers[i].run() on an array declared as Thread[].
_hit(_, _, c, names, _, _) if {
	contains(c, "].run()")
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.])(?:this\.)?(\w+)\s*\[[^\]]*\]\.run\(\)`, c, -1)
	concat("", [m[1], "[]"]) in names
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, ".run()")
	contains(content, "Thread")
	types := _thread_types(content, lang)
	names := _names(content, lang, types)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".run()")
	not helpers.is_comment_line(line)
	c := _code(line)
	contains(c, ".run()")
	_hit(lines, i, c, names, types, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "Thread.run() called directly: the work runs synchronously on the calling thread and no new thread starts. Call start()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
