# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_497

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-497",
	"name": "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
	"description": "System information sent to an HTTP client. Sources: System.getProperty() of a platform key (os.name/version/arch, java.version/vendor/home/class.path/library.path/io.tmpdir/vm.*, user.home/dir/name, sun.*), System.getenv(), System.getProperties(), InetAddress.getLocalHost() and ManagementFactory MXBeans. Sinks: response.getWriter()/getOutputStream() print/println/write/append/printf/format, a writer variable (out, writer, pw) in a file that obtains the response writer, ResponseEntity.ok()/.body(), JAX-RS Response.ok()/.entity() (in a file importing javax/jakarta.ws.rs), a return from a @*Mapping handler in a @RestController/@ResponseBody class, Model.addAttribute()/ModelAndView.addObject(), and JSP <%= %> expressions and out.print. Reported when the source is in the sink's argument, or assigned within 25 lines above (one intermediate assignment allowed, unless it builds a File/Path or a boolean test from the value). Not reported: logging, console output (System.out), using the value to build paths or branch on the OS, application-defined properties (System.getProperty(\"acme.mode\")), and the patterns in comments or string literals. Stack traces and exception messages are a separate weakness (CWE-209).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-497/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [497],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["information-exposure-system", "cwe-497"],
}

_src_re := `\bSystem\.getProperty\s*\(\s*__(?:os\.(?:name|version|arch)|java\.(?:version|vendor|home|class\.path|library\.path|runtime\.version|io\.tmpdir|vm\.[\w.]+)|user\.(?:home|dir|name)|sun\.[\w.]+)\b|\bSystem\.(?:getenv|getProperties)\s*\(|\bInetAddress\.getLocalHost\s*\(|\bManagementFactory\.get\w+MXBean\s*\(`

_writer_sink := `\b\w*(?:[Rr]esponse|resp|res)\s*\.\s*(?:getWriter|getOutputStream)\s*\(\s*\)\s*\.\s*(?:print|println|write|append|printf|format)\s*\(`

_var_sink := `(?:^|[^\w.])(?:out|writer|pw|printWriter|respWriter)\s*\.\s*(?:print|println|write|append|printf|format)\s*\(`

_entity_sink := `\bResponseEntity\s*\.\s*ok\s*\(|\)\s*\.\s*body\s*\(`

_jaxrs_sink := `\bResponse\s*\.\s*ok\s*\(|\.\s*entity\s*\(`

# An intermediate value that is a path, a file or a boolean test built from
# the source does not carry the information itself.
_derived_not_text := `\bnew\s+File\s*\(|\bPaths?\s*\.\s*(?:get|of)\s*\(|\.\s*(?:resolve|startsWith|endsWith|equals\w*|contains|matches|exists|isEmpty)\s*\(|^\s*(?:final\s+)?(?:boolean|int|long|File|Path)\s+\w+\s*=`

_model_sink := `\b(?:model|modelMap|map|mav|modelAndView)\s*\.\s*(?:addAttribute|addObject)\s*\(`

# String literals blanked, so a source or sink spelled in a message is text.
# The key of System.getProperty("os.name") is kept first, as __os.name.
_code(line) := regex.replace(regex.replace(line, `(System\.getProperty\s*\(\s*)"([\w.]+)"`, "${1}__${2}"), `"(?:[^"\\]|\\.)*"`, `""`)

_sinks(path, content) := s if {
	endswith(path, ".java")
	s := {re |
		some re in [_writer_sink, _var_sink, _entity_sink, _jaxrs_sink, _model_sink]
		_sink_enabled(re, content)
	}
}

_sinks(path, _) := {`<%=`, _var_sink} if endswith(path, ".jsp")

_sink_enabled(re, _) if re == _writer_sink

_sink_enabled(re, _) if re == _model_sink

_sink_enabled(re, content) if {
	re == _var_sink
	regex.match(`\.get(?:Writer|OutputStream)\s*\(`, content)
}

_sink_enabled(re, content) if {
	re == _jaxrs_sink
	regex.match(`\b(?:javax|jakarta)\.ws\.rs\b`, content)
}

_sink_enabled(re, content) if {
	re == _entity_sink
	contains(content, "ResponseEntity")
}

_after(re, c) := concat(" ", array.slice(parts, 1, count(parts))) if parts := regex.split(re, c)

# The text that leaves the server on line i: the sink's arguments.
_outs(path, content, lines, i, c) := {_after(re, c) | some re in _sinks(path, content); regex.match(re, c)} | {_after(`^\s*return\b`, c) | _returns(path, content, lines, i, c)}

_returns(path, content, lines, i, c) if {
	endswith(path, ".java")
	regex.match(`^\s*return\b`, c)
	regex.match(`@RestController|@ResponseBody`, content)
	_in_handler(lines, i)
}

# The nearest method declaration above line i is annotated as a request
# mapping (the annotation within the three lines over it).
_in_handler(lines, i) if {
	decls := [d |
		some d in numbers.range(max([0, i - 40]), i - 1)
		regex.match(`^\s*(?:public|protected|private)\s[^=;]*\(`, lines[d])
	]
	count(decls) > 0
	d := max(decls)
	some k in numbers.range(max([0, d - 3]), d)
	regex.match(`@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b|@ResponseBody\b`, lines[k])
}

_exposes(lines, i, out) if regex.match(_src_re, out)

_exposes(lines, i, out) if {
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_src_re, _code(prev))
	v := helpers.assigned_ident(prev)
	_reaches(lines, j, i, v, out)
}

_reaches(_, _, _, v, out) if regex.match(concat("", [`\b`, v, `\b`]), out)

_reaches(lines, j, i, v, out) if {
	i - 1 >= j + 1
	some k in numbers.range(j + 1, i - 1)
	mid := lines[k]
	not helpers.is_comment_line(mid)
	regex.match(concat("", [`\b`, v, `\b`]), mid)
	not regex.match(_derived_not_text, mid)
	w := helpers.assigned_ident(mid)
	w != v
	regex.match(concat("", [`\b`, w, `\b`]), out)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".jsp"}
	endswith(path, ext)
	regex.match(`System\.(?:getProperty|getenv|getProperties)|getLocalHost|MXBean`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	c := _code(line)
	some out in _outs(path, content, lines, i, c)
	_exposes(lines, i, out)
	finding := {
		"rule_id": metadata.id,
		"message": "System information (JVM, OS, paths, environment or host name) is sent to the HTTP client; it tells an attacker what to target. Remove it from the response or restrict it to an authenticated admin endpoint",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
