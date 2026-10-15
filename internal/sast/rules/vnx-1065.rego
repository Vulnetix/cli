# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1065

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1065",
	"name": "Runtime Resource Management Control Element in a Component Built to Run on Application Servers",
	"description": "Java: a component that runs inside an application server or servlet container (a class extending HttpServlet/GenericServlet, an EJB annotated @Stateless/@Stateful/@Singleton/@MessageDriven, a @WebServlet/@WebFilter/@WebListener, a @ServerEndpoint WebSocket endpoint, a JAX-RS resource, or a Spring @Controller/@RestController, or a file importing javax/jakarta servlet, EJB, JAX-RS or WebSocket APIs) that manages the JVM or its threads itself: System.exit(), Runtime.getRuntime().exit()/halt() (also split across lines, or through a variable assigned Runtime.getRuntime()), new Thread(...), or an unmanaged java.util.concurrent.Executors.new...() pool. Exiting stops the whole server and every other application on it; unmanaged threads escape the container's lifecycle, security context and thread-pool limits (use a ManagedExecutorService or the framework's task executor). Not reported: the same calls in command-line programs and other classes with no container API, inside a `static void main` (a launcher that boots an embedded server), in test sources, Thread.currentThread() and other Thread static methods, ThreadLocal and Thread arrays, lookalike identifiers, and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1065/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1065],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["runtime-mgmt-in-app-server", "app-server", "java", "cwe-1065"],
}

_component_re := `(?:\bextends\s+(?:javax\.servlet\.|jakarta\.servlet\.)?(?:http\.)?(?:HttpServlet|GenericServlet)\b|@(?:Stateless|Stateful|MessageDriven|Singleton|WebServlet|WebFilter|WebListener|ServerEndpoint|RestController|Controller|Path)\b|\bimport\s+(?:javax|jakarta)\.(?:servlet|ejb|ws\.rs|websocket)\.)`

# System.exit, Runtime.getRuntime().exit/halt, new Thread(, and the
# unmanaged pools of java.util.concurrent.Executors.
_sink_re := `(?:\bSystem\s*\.\s*exit\s*\(|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*(?:exit|halt)\s*\(|\bnew\s+(?:java\.lang\.)?Thread\s*\(|\bExecutors\s*\.\s*new\w+\s*\()`

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_indent(line) := count(line) - count(trim_left(line, " \t"))

_sink(_, _, s, _) if regex.match(_sink_re, s)

# Runtime.getRuntime()
#         .exit(2);
_sink(lines, i, s, _) if {
	regex.match(`\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*$`, s)
	i + 1 < count(lines)
	regex.match(`^\s*\.\s*(?:exit|halt)\s*\(`, lines[i + 1])
}

# Runtime rt = Runtime.getRuntime(); ... rt.halt(0);
_sink(_, _, s, rts) if {
	some v in rts
	regex.match(concat("", [`\b`, v, `\s*\.\s*(?:exit|halt)\s*\(`]), s)
}

_runtime_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*;`, content, -1)
}

_member_re := `^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract)\s+)+(?:<[^>]*>\s*)?[\w.<>\[\],? ]+\s+([A-Za-z_]\w*)\s*\(`

# The sink is inside `static void main(...)`: a launcher that boots an
# embedded container, not a component running inside one.
_in_main(lines, i) if {
	ii := _indent(lines[i])
	decls := [k |
		some k in numbers.range(max([0, i - 120]), i - 1)
		_indent(lines[k]) < ii
		regex.match(_member_re, lines[k])
	]
	count(decls) > 0
	d := lines[max(decls)]
	regex.match(`\bstatic\b[^(]*\bvoid\s+main\s*\(`, d)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?:System\s*\.\s*exit|getRuntime|new\s+(?:java\.lang\.)?Thread\s*\(|Executors\s*\.\s*new)`, content)
	regex.match(_component_re, content)
	rts := _runtime_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:exit|getRuntime|Thread|halt|Executors)`, line)
	not helpers.is_comment_line(line)
	_sink(lines, i, _strip(line), rts)
	not _in_main(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "JVM or thread management inside an application-server component (System.exit, Runtime.exit/halt, new Thread, Executors pool): it stops the whole server or escapes the container's lifecycle; return an error or use a managed executor",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
