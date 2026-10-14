package vulnetix.rules.vnx_py_014

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-014",
	"name": "Python XML external entity injection",
	"description": "An XML parser is configured, or used, so that it resolves external entities, letting a document read local files or make the server fetch URLs (XXE). Reported: a SAX parser whose external entity features are switched on (parser.setFeature(feature_external_ges or feature_external_pes, True/1), or the http://xml.org/sax/features/external-*-entities URI), which minidom and pulldom parsing then inherit; an lxml etree.XMLParser created with resolve_entities=True or no_network=False (also as a multi-line call); xmltodict.parse(..., disable_entities=False); and lxml etree.fromstring/XML/parse/iterparse given request data (directly, or a variable assigned from request data up to 25 lines above) with no parser argument, since older lxml releases resolve external entities with the default parser. Not reported: the standard library's xml.etree, minidom and sax parsers with their defaults (they do not fetch external entities on current Python), xml.etree imported under the name etree, defusedxml, lxml with an explicit parser or a constant/file-path argument, setFeature(..., False), and the pattern in comments and strings. Entity-expansion denial of service (billion laughs, huge_tree) is not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-014/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-201"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xxe", "xml", "injection", "python"],
}

_str_re := `[rRbBuU]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')`

_code(line) := regex.replace(regex.replace(line, _str_re, " QSTR "), `#.*$`, "")

_bal(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

_call_text(lines, i) := txt if {
	head := _code(lines[i])
	_bal(head) <= 0
	txt := head
}

_call_text(lines, i) := txt if {
	head := _code(lines[i])
	_bal(head) > 0
	last := min([count(lines) - 1, i + 8])
	ends := [j |
		some j in numbers.range(i + 1, last)
		_bal(concat("\n", [_code(lines[k]) | some k in numbers.range(i, j)])) <= 0
	]
	end := min(array.concat([last], ends))
	txt := concat("\n", [_code(lines[k]) | some k in numbers.range(i, end)])
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── SAX external entity features switched on ────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "setFeature")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setFeature")
	not helpers.is_comment_line(line)
	regex.match(`\.setFeature\s*\(`, _code(line))
	regex.match(`\.setFeature\s*\(\s*(?:[\w\.]*\bfeature_external_(?:ges|pes)|["']http://xml\.org/sax/features/external-(?:general|parameter)-entities["'])\s*,\s*(?:True|1)\s*\)`, line)
	finding := _finding(path, i, line, "SAX external entity processing is switched on, so a parsed document can read local files or make the server fetch URLs (XXE); leave feature_external_ges/feature_external_pes off or parse with defusedxml")
}

# ── lxml / xmltodict parser options that resolve entities ───────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`resolve_entities|no_network|disable_entities`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`XMLParser|xmltodict`, line)
	not helpers.is_comment_line(line)
	_entity_call(_code(line), _code(line))
	finding := _finding(path, i, line, "The XML parser is configured to resolve external entities or fetch them over the network, so a parsed document can read local files or make the server fetch URLs (XXE); use XMLParser(resolve_entities=False, no_network=True) or defusedxml")
}

_entity_call(code, txt) if {
	regex.match(`(?:^|[^\w])XMLParser\s*\(`, code)
	regex.match(`\bresolve_entities\s*=\s*True\b|\bno_network\s*=\s*False\b`, txt)
}

_entity_call(code, txt) if {
	regex.match(`\bxmltodict\.parse\s*\(`, code)
	regex.match(`\bdisable_entities\s*=\s*False\b`, txt)
}

# Report the keyword line of a multi-line XMLParser call, not only the opener.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`resolve_entities|no_network|disable_entities`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(?:resolve_entities\s*=\s*True|no_network\s*=\s*False|disable_entities\s*=\s*False)\b`, line)
	some k in numbers.range(max([0, i - 8]), i - 1)
	i > 0
	regex.match(`(?:^|[^\w])XMLParser\s*\(|\bxmltodict\.parse\s*\(`, _code(lines[k]))
	_bal(concat("\n", [_code(lines[x]) | some x in numbers.range(k, i - 1)])) > 0
	finding := _finding(path, i, line, "The XML parser is configured to resolve external entities or fetch them over the network, so a parsed document can read local files or make the server fetch URLs (XXE); use XMLParser(resolve_entities=False, no_network=True) or defusedxml")
}

# ── lxml default parser over request data ───────────────────────────────

_lxml_names(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*(?:from\s+lxml\s+import\s+etree\s+as\s+(\w+)|import\s+lxml\.etree\s+as\s+(\w+))`, content, -1)
	m[1] != ""
} | {m[2] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*(?:from\s+lxml\s+import\s+etree\s+as\s+(\w+)|import\s+lxml\.etree\s+as\s+(\w+))`, content, -1)
	m[2] != ""
} | {"etree" | regex.match(`(?m)^\s*from\s+lxml\s+import\s+(?:[^\n]*,\s*)?etree\s*(?:,|$)`, content)} | {"lxml.etree" | regex.match(`(?m)^\s*import\s+lxml\.etree\s*$`, content)}

_source_re := `\brequest\.(?:args|form|values|GET|POST|FILES|data|json|get_json|body|files|get_data|stream|read)\b`

_tainted(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	contains(lines[j], "request")
	not helpers.is_comment_line(lines[j])
	regex.match(_source_re, _code(lines[j]))
	v := helpers.assigned_first(lines[j])
}

_arg_re := `^(?:[rRbBuUfF]{0,2}(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\[(?:[^\[\]]|\[[^\[\]]*\])*\]|[^,()\[\]"'])*`

_ids(arg) := {m[1] |
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)(\s*\()?`, _code(arg), -1)
	m[2] == ""
}

_tainted_arg(_, _, arg) if regex.match(_source_re, _code(arg))

_tainted_arg(lines, i, arg) if {
	some v in _ids(arg)
	v in _tainted(lines, i)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "lxml")
	names := _lxml_names(content)
	count(names) > 0
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:fromstring|XML|parse|iterparse|fromstringlist)\s*\(`, line)
	not helpers.is_comment_line(line)
	some name in names
	pat := concat("", [`(?:^|[^\w.])`, replace(name, ".", `\.`), `\.(?:fromstring|XML|parse|iterparse|fromstringlist)\s*\(`])
	regex.match(pat, _code(line))
	after := regex.split(pat, concat("\n", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 4]))]))[1]
	arg := regex.find_n(_arg_re, after, 1)[0]
	substring(after, count(arg), 1) == ")"
	_tainted_arg(lines, i, arg)
	finding := _finding(path, i, line, "Request data is parsed by lxml with the default parser, which in older lxml releases resolves external entities, so the document can read local files (XXE); pass parser=etree.XMLParser(resolve_entities=False, no_network=True) or use defusedxml.lxml")
}
