package vulnetix.rules.vnx_llm_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-LLM-001",
	"name": "LLM prompt injection via user-controlled input",
	"description": "Reports Python, JavaScript and TypeScript code that splices user-controlled input into the instruction text of an LLM prompt: an f-string or template literal interpolation, `+` concatenation, `.format()` or `%` of a value that is read from an HTTP request (Flask/Django/FastAPI `request.args/form/json/GET/POST/...`, Express/Koa `req.body/query/params`, through up to two assignments or a destructuring within the preceding 20 lines) or is named as user input (`user_input`, `userMessage`, `user_query`, `user_prompt`, ...), where the string is a prompt argument (`content`, `prompt`, `input`, `text`) of an LLM call that opens within the 10 lines above (OpenAI/Anthropic/LiteLLM/Gemini/Ollama clients, the Vercel AI SDK, LangChain `.invoke()/.predict()/.run()`, `HumanMessage`) or is assigned to a `*prompt*` variable that an LLM call follows within 15 lines. Mixing the user's text into the instructions lets it override them. Not reported: user input passed as the whole content of a user-role message, LangChain template variables filled at invoke time, interpolation of server-side values, logging lines, comments and string literals, and system-prompt interpolation, which VNX-LLM-004 reports. Flows across functions or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-001/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [77],
	"capec": ["CAPEC-137"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["llm", "prompt-injection", "ai-security"],
}

_exts := [".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"]

_lang_ok(path) if {
	some e in _exts
	endswith(path, e)
}

_file_gate := `(?i)openai|anthropic|langchain|litellm|generativeai|genai|ollama|@ai-sdk|cohere|mistral|bedrock|groq|from\s+['"]ai['"]|require\(['"]ai['"]\)`

# An LLM call.
_llm_re := `\.(?:chat\.)?completions\.create\s*\(|\.messages\.(?:create|stream)\s*\(|\bChatCompletion\.create\s*\(|\bCompletion\.create\s*\(|\.responses\.create\s*\(|\.generate_content\s*\(|\b(?:litellm\.)?a?completion\s*\(|\bollama\.(?:chat|generate)\s*\(|\b(?:generateText|streamText|generateObject)\s*\(|\b\w*(?i:llm|chain|model|chat|agent)\w*\s*\.\s*(?:a?invoke|predict|stream|run|generate|complete)\s*\(|\bHumanMessage\s*\(`

# Reads of an HTTP request.
_src_re := `\brequest\.(?:args|form|values|json|data|files|GET|POST|body|query_params|path_params|get_json|cookies)\b|\bawait\s+request\.(?:json|form|body)\s*\(|\breq\.(?:body|query|params|cookies)\b|\bctx\.request\.(?:body|query)\b|\bctx\.(?:query|params)\b|\bsearchParams\.get\s*\(|\bformData\.get\s*\(|\bawait\s+req(?:uest)?\.json\s*\(`

_direct := `request\.(?:args|form|values|json|data|GET|POST|query_params)|req\.(?:body|query|params)`

_user_re := `(?i:user_?(?:input|message|msg|query|prompt|question|text|content|request))`

_system_re := `(?i)["']?role["']?\s*:\s*["']system|\bsystem\s*[=:]|SystemMessage|system_?prompt|\(\s*["']system["']\s*,`

_prompt_key := `\b(?:prompt|content|input|contents|text|question)\s*[=:]|["'](?:prompt|content|input|text)["']\s*:`

_prompt_assign := `(?i)^\s*(?:(?:export\s+)?(?:const|let|var)\s+)?\w*prompt\w*\s*(?::[^=]+)?\+?=[^=]`

_assigned(line) := v if {
	v := helpers.assigned_first(line)
}

_assigned(line) := v if {
	not helpers.assigned_first(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[^=]+=[^=>]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# const { question, topic } = req.body
_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=[^=]`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	p := trim_space(split(part, ":")[count(split(part, ":")) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, p)
	v := p
}

_tainted(lines, i) := t if {
	h1 := {v |
		i > 0
		some j in numbers.range(max([0, i - 20]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		regex.match(_src_re, l)
		v := _assigned(l)
	}
	h2 := {v |
		count(h1) > 0
		some k in numbers.range(max([0, i - 20]), i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		some n in h1
		regex.match(concat("", [`\b`, n, `\b`]), l)
		v := _assigned(l)
		not v in h1
	}
	t := h1 | h2
}

_alt(lines, i) := concat("|", array.concat([_direct, _user_re], [n | some n in _tainted(lines, i)]))

_fstrings(line) := [s |
	some m in regex.find_all_string_submatch_n("(?:^|[^\\w])(?:[rR]?[fF][rR]?(\"[^\"]*\"|'[^']*')|(`[^`]*`))", line, -1)
	s := concat("", [m[1], m[2]])
]

_interp(line, alt) if {
	some s in _fstrings(line)
	regex.match(concat("", [`\{[^{}]*\b(?:`, alt, `)\b`]), s)
}

_interp(line, alt) if regex.match(concat("", ["[\"'`]\\s*\\+\\s*(?:", alt, `)\b`]), line)

_interp(line, alt) if regex.match(concat("", [`\b(?:`, alt, ")\\b[\\w\\.\\[\\]'\"]*\\s*\\+\\s*[\"'`]"]), line)

_interp(line, alt) if regex.match(concat("", [`["']\s*\.format\([^)]*\b(?:`, alt, `)\b`]), line)

_interp(line, alt) if regex.match(concat("", [`["']\s*%\s*\(?\s*(?:`, alt, `)\b`]), line)

_llm_near(lines, a, b) if {
	some j in numbers.range(max([0, a]), min([count(lines) - 1, b]))
	not helpers.is_comment_line(lines[j])
	regex.match(_llm_re, lines[j])
}

_context(lines, i, line) if regex.match(_llm_re, line)

_context(lines, i, line) if {
	regex.match(_prompt_key, line)
	_llm_near(lines, i - 10, i - 1)
}

_context(lines, i, line) if {
	regex.match(_prompt_assign, line)
	_llm_near(lines, i + 1, i + 15)
}

_system_line(lines, i, line) if regex.match(_system_re, line)

_system_line(lines, i, _) if {
	some j in numbers.range(max([0, i - 2]), i - 1)
	j >= 0
	regex.match(`(?i)["']?role["']?\s*:\s*["']system`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang_ok(path)
	regex.match(_file_gate, content)
	regex.match(_llm_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match("[{+%`]|format\\(", line)
	not helpers.is_comment_line(line)
	_context(lines, i, line)
	not _system_line(lines, i, line)
	not regex.match(`(?i)\b(?:log(?:ger)?|console|logging|print)\b\s*[\.(]`, line)
	_interp(line, _alt(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input is spliced into LLM prompt instructions; keep instructions in a fixed system prompt and pass user text as a separate user message, delimited and treated as data",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
