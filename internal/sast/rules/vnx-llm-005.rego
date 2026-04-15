package vulnetix.rules.vnx_llm_005

import rego.v1

metadata := {
	"id": "VNX-LLM-005",
	"name": "LangChain arbitrary code execution tool",
	"description": "LangChain tools that allow arbitrary code execution (PythonREPLTool, BashProcess, PythonAstREPLTool, LLMMathChain, create_python_agent) are present in the codebase. When an LLM agent can invoke these tools, prompt injection attacks can escalate to full remote code execution on the host. Use sandboxed execution environments or restrict available tools to safe, purpose-built actions.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-005/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["langchain", "rce", "llm", "ai-security"],
}

_is_py(path) if endswith(path, ".py")

_dangerous_tools := [
	"PythonREPLTool(",
	"PythonREPLTool()",
	"BashProcess(",
	"BashProcess()",
	"PythonAstREPLTool(",
	"PythonAstREPLTool()",
	"LLMMathChain(",
	"create_python_agent(",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some tool in _dangerous_tools
	contains(line, tool)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("LangChain arbitrary code execution tool '%v' detected; prompt injection attacks against the LLM agent can lead to RCE — use sandboxed execution or restrict available tools", [tool]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
