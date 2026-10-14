package vulnetix.rules.vnx_llm_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-LLM-002",
	"name": "LLM output passed to code execution (RCE)",
	"description": "Reports model output reaching a code or shell execution sink in Python, JavaScript or TypeScript. The source is an LLM response read as text (`.choices[0].message.content`, `.choices[0].text`, Anthropic `.content[0].text`, `.output_text`, or the result of `llm/chain/model/agent/chat.invoke()/predict()/run()/generate()` and `generate_content()`), used directly or through up to two assignments within the preceding 25 lines. The sinks are Python eval(), exec() (also exec(compile(...))), os.system(), os.popen() and subprocess.run/call/Popen/check_output/check_call/getoutput(), and JavaScript eval(), new Function(), vm.runInNewContext/runInThisContext/runInContext() and child_process exec()/execSync(). Prompt injection steers the model, so whoever controls the prompt or any document it reads then runs code on the host. Not reported: tool-call arguments parsed with json.loads/JSON.parse and dispatched to fixed handlers, ast.literal_eval(), a regex .exec(), execFile with constant arguments, execution of values that do not come from a model response, and the pattern inside a comment or string literal. Flows across functions or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-002/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [95],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["llm", "code-injection", "rce", "ai-security"],
}

_exts := [".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"]

_lang_ok(path) if {
	some e in _exts
	endswith(path, e)
}

# An LLM response read as text.
_source_re := `\.choices\s*\[\s*0\s*\]\s*\.\s*(message\s*\.\s*content|text)\b|\.content\s*\[\s*0\s*\]\s*\.\s*text\b|\.output_text\b|\b\w*(?i:llm|chain|model|agent|chat)\w*\s*\.\s*(a?invoke|predict|run|generate)\s*\(|\.generate_content\s*\(`

_file_gate := `choices|content\s*\[\s*0\s*\]|output_text|invoke\s*\(|predict\s*\(|\.run\s*\(|generate`

_sink_gate := `\b(eval|exec|execSync|system|popen|subprocess|Function|runInNewContext|runInThisContext|runInContext)\b`

# Sinks; the last group is the text after the opening parenthesis.
_py_sink := `(?:(?:^|[^\w\.])(?:eval|exec)|\bos\.(?:system|popen)|\bsubprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput))\s*\((.*)$`

_js_sink := `(?:(?:^|[^\w\.])(?:eval|exec|execSync)|\bchild_process\.(?:exec|execSync)|\bvm\.(?:runInNewContext|runInThisContext|runInContext)|\bnew\s+vm\.Script|\bnew\s+Function)\s*\((.*)$`

_sink_re(path) := _py_sink if endswith(path, ".py")

_sink_re(path) := _js_sink if not endswith(path, ".py")

_strip(line) := regex.replace(line, "\"[^\"]*\"|'[^']*'|`[^`]*`", `""`)

# The name a line assigns, including a TypeScript `const x: T = ...`.
_assigned(line) := v if {
	v := helpers.assigned_first(line)
}

_assigned(line) := v if {
	not helpers.assigned_first(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[^=]+=[^=>]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# Names assigned from a model response, and names assigned from those (two hops).
_hop1(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_source_re, l)
	v := _assigned(l)
}

_tainted(lines, i) := t if {
	h1 := _hop1(lines, i)
	h2 := {v |
		count(h1) > 0
		some k in numbers.range(max([0, i - 25]), i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		some n in h1
		regex.match(concat("", [`\b`, n, `\b`]), l)
		v := _assigned(l)
		not v in h1
	}
	t := h1 | h2
}

# The argument text of the sink: the rest of its line, or the next line when
# the call breaks right after the parenthesis.
_arg(lines, i, rest) := a if {
	trim_space(rest) != ""
	a := trim_space(rest)
}

_arg(lines, i, rest) := a if {
	trim_space(rest) == ""
	i + 1 < count(lines)
	a := trim_space(lines[i + 1])
}

_first(arg) := regex.replace(arg, `,.*$`, "")

_reaches(arg, _, _) if regex.match(_source_re, _first(arg))

_reaches(arg, names, _) if {
	some n in names
	regex.match(concat("", [`^(?:compile\s*\(\s*)?`, n, `\b`]), arg)
}

# new Function('a', 'b', body): the body is the last argument.
_reaches(arg, names, rest_line) if {
	regex.match(`new\s+Function\s*\(`, rest_line)
	some n in names
	regex.match(concat("", [`\b`, n, `\b`]), arg)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang_ok(path)
	regex.match(_file_gate, content)
	regex.match(_sink_gate, content)
	lines := split(content, "\n")
	sink := _sink_re(path)
	some i, line in lines
	regex.match(_sink_gate, line)
	not helpers.is_comment_line(line)
	regex.match(sink, _strip(line))
	m := regex.find_all_string_submatch_n(sink, line, 1)
	count(m) > 0
	arg := _arg(lines, i, m[0][1])
	_reaches(arg, _tainted(lines, i), line)
	finding := {
		"rule_id": metadata.id,
		"message": "LLM response text reaches eval/exec or a shell; a prompt-injected model then runs code on the host. Use structured tool calls dispatched to fixed handlers, or a sandbox with no host access",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
