# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_839

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-839",
	"name": "Numeric Range Comparison Without Minimum Check",
	"description": "A signed integer read from untrusted input is checked only against a maximum and then used as an array or list index. Python: int() of request.*, sys.argv or input(); Java: Integer.parseInt/valueOf, Long.parseLong of getParameter()/getHeader() or of a variable assigned from one a few lines above, or Scanner.nextInt(); C/C++: atoi/atol/strtol, std::stoi/stol, or sscanf with %d/%i into a signed variable. The value is compared with an upper bound (if idx < len(items), if (slot > 63) return, if (i >= 16)) within six lines of being read, and indexes an array (or a Java List through .get(i)) within eight lines of the check, with no lower-bound check in between: a negative value passes, and indexes from the end in Python, throws in Java and reads or writes out of bounds in C. Not reported: a range check that also tests the minimum (0 <= i < n, i < 0 || i >= n, i >= 0 && ..., i < 1, i <= 0), a value clamped by max(0, ...)/Math.max(0, ...)/abs() or validated with isdigit(), unsigned/size_t/strtoul values, constants, and values that are compared but never used as an index. Flows through helper functions are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-839/",
	"languages": ["python", "java", "c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [839],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["numeric-range", "bounds-check", "negative-index", "cwe-839"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "c" if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
	endswith(path, ext)
}

_gate := {
	"py": "int(",
	"java": "Integer.",
	"c": "ato",
}

_source_re := {
	"py": `\bint\s*\(\s*(?:(?:flask\.|self\.)?request\.|sys\.argv|input\s*\()`,
	"java": `\b(?:Integer\.(?:parseInt|valueOf)|Long\.(?:parseLong|valueOf)|Short\.parseShort)\s*\(\s*\w+\.get(?:Parameter|Header)\s*\(|\.nextInt\s*\(\s*\)`,
	"c": `\b(?:atoi|atol|atoll|strtol|strtoll|(?:std::)?sto(?:i|l|ll))\s*\(|\bsscanf\s*\(`,
}

_c_gate(content) if contains(content, "atoi(")

_c_gate(content) if contains(content, "atol")

_c_gate(content) if contains(content, "strtol")

_c_gate(content) if contains(content, "sscanf")

_c_gate(content) if {
	contains(content, "sto")
	regex.match(`\bsto(?:i|l|ll)\s*\(`, content)
}

_content_gate := {
	"py": _source_re.py,
	"java": `\.get(?:Parameter|Header)\s*\(|\.nextInt\s*\(`,
	"c": _source_re.c,
}

_line_gate := {
	"py": _source_re.py,
	"java": `\b(?:Integer\.(?:parseInt|valueOf)|Long\.(?:parseLong|valueOf)|Short\.parseShort)\s*\(|\.nextInt\s*\(\s*\)`,
	"c": _source_re.c,
}

# The variable that receives the parsed value.
_source_var(lang, _, _, src) := v if {
	regex.match(_source_re[lang], src)
	not contains(src, "sscanf")
	v := helpers.assigned_first(src)
}

# sscanf(line, "%d", &idx): the last &name receives a signed conversion.
_source_var("c", _, _, src) := v if {
	contains(src, "sscanf")
	m := regex.find_all_string_submatch_n(`\bsscanf\s*\(.*"[^"]*%(?:hh|h|l|ll)?[di][^"]*".*&\s*(\w+)\s*\)`, src, 1)
	count(m) > 0
	v := m[0][1]
}

# Java, two steps: String raw = req.getParameter("i"); int i = Integer.parseInt(raw);
_source_var("java", lines, j, src) := v if {
	not regex.match(_source_re.java, src)
	m := regex.find_all_string_submatch_n(`\b(?:Integer\.(?:parseInt|valueOf)|Long\.(?:parseLong|valueOf)|Short\.parseShort)\s*\(\s*(\w+)\s*\)`, src, 1)
	count(m) > 0
	m[0][1] in helpers.tainted_names(lines, j, 5, `\.get(?:Parameter|Header)\s*\(`)
	v := helpers.assigned_first(src)
}

_indexes(_, v, line) if regex.match(_index_re(v), line)

_indexes("java", v, line) if regex.match(concat("", [`\.get\s*\(\s*`, v, `\s*\)`]), line)

_file_gate("c", content) if _c_gate(content)

_file_gate(lang, content) if {
	lang != "c"
	contains(content, _gate[lang])
}

_file_gate("java", content) if {
	not contains(content, "Integer.")
	regex.match(`Long\.|Short\.|nextInt`, content)
}

_compare_re(v) := concat("", [`\b`, v, `\s*(?:<=?|>=?)\s*[^\s=]|[\w\)\]]\s*(?:<=?|>=?)\s*`, v, `\b`])

_lower_re(v) := concat("", [
	`\b`, v, `\s*(?:<=?|>=?)\s*-?[01]\b|\b`, v, `\s*>=?\s*-\d|(?:^|[^\w.])-?[01]\s*(?:<=?|>=?)\s*`, v, `\b`,
	`|\b(?:Math\.)?(?:max|abs)\s*\(|isdigit|isdecimal|isnumeric`,
])

_index_re(v) := concat("", [`[\w\)\]]\s*\[\s*`, v, `\s*\]`])

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_file_gate(lang, content)
	regex.match(_content_gate[lang], content)
	lines := split(content, "\n")
	some j, src in lines
	regex.match(_line_gate[lang], src)
	not helpers.is_comment_line(src)
	not regex.match(`^\s*(?:unsigned|size_t|uint\w*|UINT\w*|DWORD)\b`, src)
	v := _source_var(lang, lines, j, src)
	some i in numbers.range(j + 1, min([count(lines) - 1, j + 6]))
	check := lines[i]
	regex.match(`\b(?:if|while|elif)\b`, check)
	not helpers.is_comment_line(check)
	regex.match(_compare_re(v), check)
	some k in numbers.range(i, min([count(lines) - 1, i + 8]))
	not helpers.is_comment_line(lines[k])
	_indexes(lang, v, lines[k])
	window := concat("\n", [lines[m] | some m in numbers.range(j, k); not helpers.is_comment_line(lines[m])])
	not regex.match(_lower_re(v), window)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' comes from untrusted input and is checked only against a maximum before it is used as an index: a negative value passes the check. Also reject values below 0", [v]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": check,
	}
}
