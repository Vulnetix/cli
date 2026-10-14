package vulnetix.rules.vnx_llm_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-LLM-005",
	"name": "LangChain arbitrary code execution tool",
	"description": "Reports Python code that hands an LLM agent a code or shell execution capability through LangChain: instantiating PythonREPLTool, PythonAstREPLTool, PythonREPL, ShellTool or BashProcess, calling create_python_agent(), building LLMMathChain or PALChain (both have had prompt-to-code-execution CVEs), load_tools() naming \"python_repl\" or \"terminal\" (on the call line or its continuation lines), and allow_dangerous_code=True on an agent or chain constructor (create_pandas_dataframe_agent, create_csv_agent and others). Prompt injection against such an agent is remote code execution on the host. Not reported: imports alone, safe tools (search, Wikipedia), load_tools() with other tool names, allow_dangerous_code=False, lookalike class names (MyPythonREPLToolConfig), and the names inside comments, docstrings or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-005/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["langchain", "rce", "llm", "ai-security"],
}

_file_gate := `PythonREPL|PythonAstREPLTool|ShellTool|BashProcess|create_python_agent|LLMMathChain|PALChain|load_tools|allow_dangerous_code`

_tool_re := `(?:^|[^\w\.])(PythonREPLTool|PythonAstREPLTool|PythonREPL|ShellTool|BashProcess|create_python_agent|LLMMathChain|PALChain)\s*(?:\(|\.from_\w+\s*\()`

_strip(line) := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)

_message(name) := sprintf("LangChain code execution capability '%v' given to an LLM agent; prompt injection then runs code on the host. Remove it, or run it in an isolated sandbox with no host access", [name])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_file_gate, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_tool_re, _strip(line), 1)
	count(m) > 0
	finding := _finding(path, i, line, m[0][1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "allow_dangerous_code")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "allow_dangerous_code")
	not helpers.is_comment_line(line)
	regex.match(`\ballow_dangerous_code\s*=\s*True\b`, _strip(line))
	finding := _finding(path, i, line, "allow_dangerous_code=True")
}

# load_tools(["terminal", "python_repl"], ...): the tool names follow on the
# call line or within its next three lines.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "load_tools")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "load_tools")
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w\.])load_tools\s*\(`, _strip(line))
	call := concat("\n", array.slice(lines, i, min([count(lines), i + 4])))
	ms := regex.find_all_string_submatch_n(`load_tools\s*\(\s*\[([^\]]*)\]`, call, 1)
	count(ms) > 0
	regex.match(`["'](python_repl|terminal)["']`, ms[0][1])
	finding := _finding(path, i, line, "load_tools(python_repl/terminal)")
}

_finding(path, i, line, name) := {
	"rule_id": metadata.id,
	"message": _message(name),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
