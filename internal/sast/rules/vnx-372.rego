# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_372

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-372",
	"name": "Incomplete Internal State Distinction",
	"description": "A substring or element search whose result has three states (not found, found at position 0, found later) is tested as a boolean, so two of the states are treated as one. Reported in Python: str.find()/rfind() used directly as a condition (if/elif/while/assert, an and/or operand, the left operand of and/or after return, a conditional expression, bool()) or compared with True/False, which treats 'not found' (-1) as found and a match at index 0 as missing. Reported in PHP: strpos/stripos/strrpos/strripos (also mb_ and iconv_ forms) and array_search used as a condition, negated with !, used in a ternary, or loosely compared (==, !=, <>) with false, true, null or 0, which conflates 'not found' (false) with a match at offset 0. Reported in JavaScript/TypeScript: indexOf/lastIndexOf/findIndex (also _.findIndex) and String search() with a regex or string literal used directly as an if/while condition, a && or || operand, the left operand of && after return, a ternary test, or loosely compared with true/false, which treats -1 as found and index 0 as missing. Not reported: comparisons with -1, >= 0, > -1, !== false or === 0; the starts-with idioms not s.find(x) and !s.indexOf(x) (true only at index 0) and ~s.indexOf(x); a result assigned and checked later; BeautifulSoup, ElementTree, lxml, Selenium and MongoDB find() (files that import them, receivers named soup/tree/root/node/element and keyword-argument calls); find() in a Python file that defines its own find() method; a search() on anything but a literal pattern (a search client); in, includes() and str_contains(); comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-372/",
	"languages": ["python", "php", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [372],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["internal-state-distinction", "return-value", "cwe-372"],
}

# Call arguments with up to two levels of nested parentheses.
_args := `\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

# String literals are blanked so a pattern quoted in a message, a docstring
# or a test description is not code.
_strip(line) := regex.replace(regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`), "`[^`]*`", "``")

# ── Python ──────────────────────────────────────────────────────────────

_py_recv := `[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\(\)|\[[^\]]*\])*`

_py_call := concat("", [`(`, _py_recv, `)\.r?find`, _args])

_py_res := [
	# if/elif/while/assert/and/or <call> followed by a boolean consumer
	concat("", [`\b(?:if|elif|while|assert|and|or)\s+\(?\s*`, _py_call, `\s*(?::|\band\b|\bor\b|\belse\b|\)\s*:|,|$)`]),
	concat("", [`\bbool\(\s*`, _py_call, `\s*\)`]),
	concat("", [_py_call, `\s*(?:==|!=|\bis\s+not\b|\bis\b)\s*(?:True|False)\b`]),
	# return s.find(x) and ...: the result is the left operand of a boolean
	concat("", [`\breturn\s+\(?\s*`, _py_call, `\s*(?:\band\b|\bor\b)`]),
]

_py_other_find_import := `(?m)^\s*(?:from|import)\s+(?:bs4|lxml|xml\.|selenium|pymongo|motor|playwright|scrapy|parsel|pyquery|html5lib|defusedxml|mongoengine)\b`

_py_dom_recv := `(?i)(?:^|\.)(?:soup|tree|root|elem|element|el|node|tag|doc|dom|driver|browser|page|collection|coll|db|xml|html|parent|child|item)$`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "find(")
	not regex.match(_py_other_find_import, content)
	# a class of the file defines its own find(), whose result is not an index
	not regex.match(`(?m)^\s+def\s+r?find\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "find(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	some re in _py_res
	some m in regex.find_all_string_submatch_n(re, code, -1)
	not regex.match(_py_dom_recv, m[1])
	not regex.match(`find\([^)]*\b[A-Za-z_]\w*\s*=[^=]`, m[0])
	f := _finding(path, i, line, "str.find()/rfind() is used as a boolean: it returns -1 when the text is absent (truthy) and 0 when it is at the start (falsy), so the two states are swapped. Use 'x in s', s.startswith(x), or compare the result with -1")
}

# ── PHP ─────────────────────────────────────────────────────────────────

# array_search() has the same false-or-0 result as strpos().
_php_call := concat("", [`\b(?:(?:mb_|iconv_)?str(?:i|r|ri)?pos|array_search)\s*`, _args])

_php_res := [
	concat("", [`(?i)(?:\b(?:if|elseif|while)\s*\(\s*|&&\s*|\|\|\s*|\b(?:and|or|xor)\s+)!?\s*`, _php_call, `\s*(?:\)|&&|\|\||\b(?:and|or|xor)\b)`]),
	concat("", [`(?i)!\s*`, _php_call]),
	concat("", [`(?i)(?:[^=!<>]=|[(,?:]|\breturn\b|\becho\b|&&|\|\|)\s*`, _php_call, `\s*\?[^?:>]`]),
	concat("", [`(?i)`, _php_call, `\s*(?:==|!=|<>)\s*(?:false|true|null|0)\b`]),
	concat("", [`(?i)\b(?:false|true|null|0)\s*(?:==|!=|<>)\s*`, _php_call]),
]

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`pos|array_search`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`pos|array_search`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some re in _php_res
	regex.match(re, code)
	f := _finding(path, i, line, "strpos()-family result is used as a boolean or compared loosely: it returns false when the needle is absent and 0 when it is at the start, and both are falsy, so a match at offset 0 is treated as no match. Compare with !== false / === 0, or use str_contains()/str_starts_with()")
}

# ── JavaScript / TypeScript ─────────────────────────────────────────────

_js_ext := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"}

# String.prototype.search() returns -1 or an index too; only a call whose
# argument is a regex or string literal is taken as the string method.
_js_call := concat("", [`[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\([^()]*\)|\[[^\]]*\])*(?:\.(?:indexOf|lastIndexOf|findIndex)`, _args, `|\.search\(\s*(?:/(?:[^/\\\n]|\\.)+/[a-z]*|""|'')\s*\))`])

_js_res := [
	concat("", [`(?:\b(?:if|while)\s*\(\s*|&&\s*|\|\|\s*)`, _js_call, `\s*(?:\)|&&|\|\|)`]),
	concat("", [`(?:[^=!<>]=|[(,?:]|\breturn\b|&&|\|\|)\s*`, _js_call, `\s*\?[^?.:]`]),
	concat("", [_js_call, `\s*(?:==|!=)\s*(?:true|false)\b`]),
	# return a.indexOf(x) && ...: the result is the left operand of &&
	concat("", [`\breturn\s+\(?\s*`, _js_call, `\s*&&`]),
]

findings contains f if {
	some path, content in input.file_contents
	some ext in _js_ext
	endswith(path, ext)
	not endswith(path, ".min.js")
	regex.match(`ndexOf\(|findIndex\(|\.search\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`ndexOf\(|findIndex\(|\.search\(`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some re in _js_res
	regex.match(re, code)
	f := _finding(path, i, line, "indexOf()/lastIndexOf()/findIndex() is used as a boolean: it returns -1 when nothing matches (truthy) and 0 for a match at the start (falsy), so the two states are swapped. Use includes()/some()/startsWith(), or compare the result with -1")
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
