# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1427

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1427",
	"name": "Improper Neutralization of Input Used for LLM Prompting: request data in the system prompt",
	"description": "Reports Go, Java, PHP and Ruby code that places HTTP request data in the system (instruction) channel of an LLM call, where it carries the authority of the application's own instructions and can override them (prompt injection). The system slot is: Go go-openai/openai-go a ChatCompletionMessage whose Role is ChatMessageRoleSystem (its Content on the same line or the next lines of the literal), openai.SystemMessage(...), langchaingo llms.ChatMessageTypeSystem; Java Spring AI ChatClient .system(...), new SystemMessage(...), LangChain4j SystemMessage.from/systemMessage(...), ChatMessageRole.SYSTEM and ChatCompletionSystemMessageParam builders; PHP an array message with 'role' => 'system' and its 'content'; Ruby a message hash with role: \"system\" (or \"role\" => \"system\") and its content. Request data is read on that line (Go r.FormValue/PostFormValue/URL.Query()/gin c.Query/PostForm/Param/GetHeader/echo QueryParam, a body decoded with Decode(&x)/Bind(&x)/ShouldBindJSON(&x); Java getParameter/getHeader/getQueryString/getReader and @RequestParam/@PathVariable/@RequestBody/@RequestHeader parameters; PHP $_GET/$_POST/$_REQUEST/$_COOKIE, $request->input()/get()/query()/post()/all(), php://input; Ruby params, request.body/params/headers, cookies[]) or reaches it through a variable assigned from such a read within the 30 lines above. On the line that opens the system slot only the text after the marker and before the next message is read, so .system(prompt).user(question) and {role: system, ...}, {role: user, ...} on one line report only what is in the system part. Not reported: request data in a user-role message (the intended channel), in Go request data used only as a map key (personas[r.FormValue(\"p\")], an allowlist lookup), a static system prompt, server-side values (dates, constants, configuration) in it, the shapes inside comments or string literals. Python, JavaScript and TypeScript are covered by VNX-LLM-004 (system prompt) and VNX-LLM-001 (instruction text). Flows across functions or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1427/",
	"languages": ["go", "java", "php", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1427],
	"capec": ["CAPEC-137"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["prompt-injection", "llm", "ai-security", "system-prompt", "cwe-1427"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if endswith(path, ".rb")

# Cheap whole-file test before any line is split.
_needle := {"go": "System", "java": "ystem", "php": "system", "ruby": "system"}

_system := {
	"go": `\bChatMessageRoleSystem\b|\bopenai\.SystemMessage\(|\bChatMessageTypeSystem\b`,
	"java": `\bnew\s+(?:[\w.]+\.)?SystemMessage\s*\(|\bSystemMessage\.(?:from|systemMessage)\s*\(|\.system\s*\(|\bChatMessageRole\.SYSTEM\b|\bChatCompletionSystemMessageParam\b`,
	"php": `['"]role['"]\s*=>\s*['"]system['"]`,
	"ruby": `\brole:\s*['"]system['"]|['"]role['"]\s*=>\s*['"]system['"]|:role\s*=>\s*['"]system['"]`,
}

_source := {
	"go": `\.(?:FormValue|PostFormValue|DefaultQuery|PostForm|DefaultPostForm|Param|GetHeader|QueryParam|FormParams|QueryParams)\(|\.URL\.Query\(\)|\.Header\.Get\(|\bc\.Query\(|\bctx\.Query\(`,
	"java": `\.(?:getParameter|getParameterValues|getHeader|getQueryString|getReader|getInputStream|getPathInfo)\(`,
	"php": `\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->(?:input|get|query|post|all|json|getParsedBody)\(|\brequest\(\)->|php://input`,
	"ruby": `\bparams\b|\brequest\.(?:body|params|query_string|headers|raw_post)\b|\bcookies\[`,
}

# A later line that opens another message or closes this one ends the slot.
_stop := `(?i)\brole\b|\.user\s*\(|UserMessage|AssistantMessage|ChatMessageRole(?:User|Assistant|Tool)|ChatMessageType(?:Human|AI|Generic|Tool)|^\s*[\}\]]`

# The match starts outside any string literal on the line.
_outside_string(line, re) if {
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	idx := indexof(line, m[0][0])
	prefix := substring(line, 0, idx)
	count(indexof_n(prefix, `"`)) % 2 == 0
	count(indexof_n(prefix, "'")) % 2 == 0
}

# ── Tainted names ──────────────────────────────────────────────────────────

_assigned("php", l) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, l, 1)
	count(m) > 0
}

_assigned("ruby", l) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(@?\w+)\s*=[^=~]`, l, 1)
	count(m) > 0
}

_assigned(lang, l) := helpers.assigned_first(l) if lang in {"go", "java"}

_tainted(lang, lines, k) := {v |
	some j in numbers.range(max([0, k - 30]), k - 1)
	l := lines[j]
	regex.match(_source[lang], l)
	not helpers.is_comment_line(l)
	v := _assigned(lang, l)
} | _bound(lang, lines, k)

# Go: a body decoded into a variable.
_bound("go", lines, k) := {m[1] |
	some j in numbers.range(max([0, k - 30]), k - 1)
	some m in regex.find_all_string_submatch_n(`\b(?:Decode|Bind|BindJSON|ShouldBind\w*|Unmarshal)\([^&)]*&(\w+)\)`, lines[j], -1)
}

# Java: annotated request parameters of the enclosing handler.
_bound("java", lines, k) := {m[1] |
	some j in numbers.range(max([0, k - 30]), k - 1)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(`@(?:RequestParam|PathVariable|RequestBody|RequestHeader|RequestPart)(?:\([^)]*\))?\s+(?:final\s+)?[\w.<>\[\]]+\s+(\w+)\s*[,)]`, lines[j], -1)
}

_bound(lang, _, _) := set() if lang in {"php", "ruby"}

_ref("php", v) := concat("", [`\$`, v, `\b`])

_ref(lang, v) := concat("", [`\b`, v, `\b`]) if lang != "php"

# ── Slot contents ──────────────────────────────────────────────────────────

_reaches(lang, _, _, line) if regex.match(_source[lang], line)

_reaches(lang, lines, k, line) if {
	some v in _tainted(lang, lines, k)
	regex.match(_ref(lang, v), line)
}

# What the slot holds on line k. On the marker line it is the text after the
# system marker up to the next message (.system(p).user(q), {Role: system,
# ...}, {Role: user, ...}), so the user turn on the same line is not read as
# the system prompt. In Go a map index (personas[r.FormValue("p")]) is an
# allowlist lookup and is dropped.
_slot_text(lang, i, k, line) := _unindex(lang, line) if k != i

_slot_text(lang, i, i, line) := _unindex(lang, _cut(suffix)) if {
	m := regex.find_all_string_submatch_n(_system[lang], line, 1)
	idx := indexof(line, m[0][0])
	suffix := substring(line, idx + count(m[0][0]), -1)
}

_stop_inline := `(?i)\brole['"]?\s*(?::|=>)|\.user\s*\(|UserMessage|AssistantMessage|ChatMessageRole(?:User|Assistant|Tool)|ChatMessageType(?:Human|AI|Generic|Tool)`

_cut(s) := substring(s, 0, indexof(s, m[0][0])) if {
	m := regex.find_all_string_submatch_n(_stop_inline, s, 1)
	count(m) > 0
}

_cut(s) := s if not regex.match(_stop_inline, s)

_unindex("go", s) := regex.replace(s, `\b\w+\[[^\[\]]*\]`, "_")

_unindex(lang, s) := s if lang != "go"

# The slot's content lines: the marker line and the following lines until a
# stop marker.
_slot_line(lines, i, i)

_slot_line(lines, i, k) if {
	k > i
	not _stopped(lines, i, k)
}

_stopped(lines, i, k) if {
	some s in numbers.range(i + 1, k)
	regex.match(_stop, lines[s])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _needle[lang])
	regex.match(_system[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _needle[lang])
	regex.match(_system[lang], line)
	not helpers.is_comment_line(line)
	_outside_string(line, _system[lang])
	some k in numbers.range(i, min([count(lines) - 1, i + 3]))
	_slot_line(lines, i, k)
	cl := lines[k]
	not helpers.is_comment_line(cl)
	_reaches(lang, lines, k, _slot_text(lang, i, k, cl))
	finding := {
		"rule_id": metadata.id,
		"message": "Request data is placed in the LLM system prompt, where it carries the authority of the application's instructions (prompt injection). Keep the system prompt static and pass user text only as a user-role message",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": cl,
	}
}
