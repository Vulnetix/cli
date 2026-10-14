package vulnetix.rules.vnx_llm_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-LLM-006",
	"name": "LLM output interpolated into SQL query",
	"description": "Reports Python code that executes SQL built from model output: the text of an LLM response (`.choices[0].message.content`, `.choices[0].text`, Anthropic `.content[0].text`, `.output_text`, or the result of `llm/chain/model/agent/chat.invoke()/predict()/run()/generate()` and `generate_content()`), read directly or through up to two assignments within the preceding 25 lines, passed as the whole query or interpolated into it (f-string, `+` concatenation, `%` or `.format()`) at a DB-API `.execute()`/`.executemany()`/`.executescript()`, SQLAlchemy `.execute(text(...))`/`exec_driver_sql()`, Django `.raw()`, `pandas.read_sql()`/`read_sql_query()` or LangChain `SQLDatabase.run()` (`db.run()`). A prompt-injected model can then emit any statement (text-to-SQL with no allowlist, or a WHERE clause written by the model). Not reported: model output passed as a bound parameter, SQL built from values that do not come from a model response (VNX-89 covers ordinary SQL injection), and the pattern in a comment or string literal. Flows across functions or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-006/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["sql-injection", "llm", "ai-security", "prompt-injection"],
}

_source_re := `\.choices\s*\[\s*0\s*\]\s*\.\s*(message\s*\.\s*content|text)\b|\.content\s*\[\s*0\s*\]\s*\.\s*text\b|\.output_text\b|\b\w*(?i:llm|chain|model|agent|chat)\w*\s*\.\s*(a?invoke|predict|run|generate)\s*\(|\.generate_content\s*\(`

_file_gate := `choices|content\s*\[\s*0\s*\]|output_text|invoke\s*\(|predict\s*\(|\.run\s*\(|generate`

_sink_gate := `\b(execute|executemany|executescript|exec_driver_sql|raw|read_sql|read_sql_query|run)\s*\(`

# The last group is the text after the call's opening parenthesis.
_sink_re := `(?:\.(?:execute|executemany|executescript|exec_driver_sql|raw)|\b(?:pd|pandas)\.read_sql(?:_query)?|\b(?:db|database|sql_db|sqldb|sql_database)\.run)\s*\(\s*(?:(?:sqlalchemy\.)?text\s*\(\s*)?(.*)$`

_strip(line) := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)

_hop1(lines, i) := helpers.tainted_names(lines, i, 25, _source_re)

_tainted(lines, i) := t if {
	h1 := _hop1(lines, i)
	h2 := {v |
		count(h1) > 0
		some k in numbers.range(max([0, i - 25]), i - 1)
		l := lines[k]
		not helpers.is_comment_line(l)
		some n in h1
		regex.match(concat("", [`\b`, n, `\b`]), l)
		v := helpers.assigned_first(l)
		not v in h1
	}
	t := h1 | h2
}

_arg(lines, i, rest) := trim_space(rest) if trim_space(rest) != ""

_arg(lines, i, rest) := trim_space(lines[i + 1]) if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

# The query is a model-response expression.
_reaches(arg, _) if regex.match(_source_re, regex.replace(arg, `,.*$`, ""))

# The query is a tainted name.
_reaches(arg, names) if {
	some n in names
	regex.match(concat("", [`^`, n, `\b\s*(?:[,)]|\.strip\(|$)`]), arg)
}

# The query interpolates a tainted name.
_reaches(arg, names) if {
	some n in names
	regex.match(concat("", [`^(?:[rR]?[fF]|[fF][rR])("""|'''|"|')[^"']*\{[^}]*\b`, n, `\b`]), arg)
}

_reaches(arg, names) if {
	some n in names
	regex.match(concat("", [`^(?:"[^"]*"|'[^']*')\s*(?:\+|%)\s*\(?\s*`, n, `\b`]), arg)
}

_reaches(arg, names) if {
	some n in names
	regex.match(concat("", [`^(?:"[^"]*"|'[^']*')\.format\([^)]*\b`, n, `\b`]), arg)
}

_reaches(arg, names) if {
	some n in names
	regex.match(concat("", [`^`, n, `\s*\+`]), arg)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(_file_gate, content)
	regex.match(_sink_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink_gate, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _strip(line))
	m := regex.find_all_string_submatch_n(_sink_re, line, 1)
	count(m) > 0
	arg := _arg(lines, i, m[0][1])
	_reaches(arg, _tainted(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "LLM response text is executed as SQL or interpolated into a query; a prompt-injected model can emit any statement. Have the model return structured filters and bind them as query parameters, or validate generated SQL against an allowlist on a read-only connection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
