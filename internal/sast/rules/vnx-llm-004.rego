package vulnetix.rules.vnx_llm_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-LLM-004",
	"name": "User input directly in LLM system prompt",
	"description": "Reports Python, JavaScript and TypeScript code that interpolates user-controlled input into an LLM system prompt: an f-string or template literal interpolation, `+` concatenation, `.format()` or `%` of a value read from an HTTP request (Flask/Django/FastAPI `request.*`, Express/Koa `req.body/query/params`, through up to two assignments or a destructuring within the preceding 20 lines) or named as user data (`user_input`, `user_name`/`userName`/`username`, `user_profile`, `user_bio`, ...), where the string is the content of a `role: system` message (on the same line or the next lines of a multi-line message), an Anthropic or Vercel AI SDK `system=`/`system:` argument (including a `\"text\":` entry within three lines of an Anthropic `system=[` content-block list), a Gemini `system_instruction=` argument, a LangChain SystemMessage, `(\"system\", ...)` tuple or `PromptTemplate.from_template(f\"...\")`, or a line inside a function or variable named as a system prompt (buildSystemPrompt, system_prompt) declared within the 8 lines above (a file with no LLM library import is still reported when it declares such a function). Instructions placed in the system role carry the most authority, so user text there can override them or leak them. Not reported: a static system prompt, server-side values (dates, tool lists, constants) in it, LangChain template variables filled at invoke time, user input in the user role (VNX-LLM-001 covers it spliced into user-role instructions), comments and string literals. Flows across functions or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-004/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [77],
	"capec": ["CAPEC-137"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["prompt-injection", "llm", "ai-security", "system-prompt"],
}

_exts := [".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"]

_lang_ok(path) if {
	some e in _exts
	endswith(path, e)
}

_file_gate := `(?i)openai|anthropic|langchain|litellm|generativeai|genai|ollama|@ai-sdk|cohere|mistral|bedrock|groq|from\s+['"]ai['"]|require\(['"]ai['"]\)`

_src_re := `\brequest\.(?:args|form|values|json|data|files|GET|POST|body|query_params|path_params|get_json|cookies)\b|\bawait\s+request\.(?:json|form|body)\s*\(|\breq\.(?:body|query|params|cookies)\b|\bctx\.request\.(?:body|query)\b|\bctx\.(?:query|params)\b|\bsearchParams\.get\s*\(|\bformData\.get\s*\(|\bawait\s+req(?:uest)?\.json\s*\(`

_direct := `request\.(?:args|form|values|json|data|GET|POST|query_params)|req\.(?:body|query|params)`

_user_re := `(?i:user_?(?:input|message|msg|query|prompt|question|text|content|request|name|profile|bio|context)|username)`

_role_system := `(?i)["']?role["']?\s*:\s*["']system["']`

# A system-prompt slot on the line itself.
_system_slot := `(?i)["']?role["']?\s*:\s*["']system["']|(?:^|[\s,(\{])system\s*[=:]\s*[^=\s]|\bSystemMessage\s*\(|\bSystemMessagePromptTemplate\b|\b(?:Chat)?PromptTemplate\.from_template\s*\(|\(\s*["']system["']\s*,`

# A declaration of a system prompt (function or variable).
_system_decl := `(?i)(?:\b(?:def|function|const|let|var)\s+\w*system_?(?:prompt|message|instructions?)\w*|^\s*\w*system_?(?:prompt|message|instructions?)\w*\s*(?::[^=]+)?\+?=[^=])`

# An LLM library is referenced, or the file declares a function named as a
# system prompt builder (a module apart from the client).
_gated(content) if regex.match(_file_gate, content)

_gated(content) if regex.match(`(?i)\b(?:def|function)\s+\w*system_?(?:prompt|message|instructions?)\w*\s*\(`, content)

_assigned(line) := v if {
	v := helpers.assigned_first(line)
}

_assigned(line) := v if {
	not helpers.assigned_first(line)
	m := regex.find_all_string_submatch_n(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*:\s*[^=]+=[^=>]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

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

_context(_, _, line) if regex.match(_system_slot, line)

# "content": ... on a line of a multi-line message whose role is system.
_context(lines, i, line) if {
	regex.match(`(?i)\bcontent["']?\s*[:=]`, line)
	not regex.match(`(?i)["']?role["']?\s*:`, line)
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(_role_system, lines[j])
	not _closed(lines, j, i)
}

# Anthropic system=[{"type": "text", "text": ...}] content blocks: the text
# entry on a line within the three lines after the system list opens.
_context(lines, i, line) if {
	regex.match(`["']text["']\s*:`, line)
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`(?:^|[\s,(\{])["']?system["']?\s*[=:]\s*\[`, lines[j])
}

_context(lines, i, line) if {
	some j in numbers.range(max([0, i - 8]), i)
	not helpers.is_comment_line(lines[j])
	regex.match(_system_decl, lines[j])
}

_closed(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	k < i
	contains(lines[k], "}")
}

findings contains finding if {
	some path, content in input.file_contents
	_lang_ok(path)
	_gated(content)
	regex.match(concat("", ["(?m)", _system_slot, "|", _system_decl]), content)
	regex.match(`(?i)system`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match("[{+%`]|format\\(", line)
	not helpers.is_comment_line(line)
	_context(lines, i, line)
	not regex.match(`(?i)\b(?:log(?:ger)?|console|logging|print)\b\s*[\.(]`, line)
	_interp(line, _alt(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input is interpolated into the LLM system prompt; keep the system prompt static and pass user data only in the user role, delimited and treated as data",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
