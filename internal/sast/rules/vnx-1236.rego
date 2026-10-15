# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1236

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1236",
	"name": "Improper Neutralization of Formula Elements in a CSV File",
	"description": "Reports a CSV export served to users (the file sets a text/csv content type, a .csv attachment or download name) that writes data rows through a CSV library without neutralising cells beginning with =, +, -, @, tab or carriage return, so a stored value such as =HYPERLINK(...) or =cmd|... runs as a formula when the download is opened in a spreadsheet. Reported: Python csv.writer/csv.DictWriter .writerow()/.writerows() and pandas .to_csv(); JavaScript json2csv (new Parser().parse, json2csv.parse), csv-stringify stringify(), fast-csv write/format, and papaparse Papa.unparse() without escapeFormulae; Java OpenCSV CSVWriter.writeNext()/writeAll() and Apache Commons CSV CSVPrinter.printRecord()/printRecords(). Not reported: header rows made only of string literals, files that neutralise formula cells (a sanitise/escape-formula helper, a check against the formula characters, defusedcsv, escapeFormulae: true), CSV written to local files with no HTTP download context, comments and test files. The download context and the neutralisation are judged on code with comment lines removed, so a Javadoc mentioning text/csv is not a download and a TODO saying sanitise is not a sanitiser. Building CSV lines by string concatenation from request data is VNX-140's finding.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1236/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1236],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["csv-injection", "cwe-1236"],
}

_msg := "Rows are written into a CSV download without neutralising cells that start with =, +, -, @, tab or CR: a stored value such as =HYPERLINK(...) executes as a formula in the recipient's spreadsheet. Prefix such cells with a single quote (or use defusedcsv / escapeFormulae)"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# The CSV is a download someone opens.
_http_csv(content) if regex.match(`(?i)text/csv|filename=?[^\n]*\.csv|attachment\(\s*['"\x60][^'"\x60]*\.csv|download_?name\s*=\s*["'][^"']*\.csv`, content)

# The file neutralises formula cells somewhere.
_sanitised(content) if regex.match(`(?i)formula|sanitiz|defusedcsv|neutrali[sz]|escape_?csv|csv_?escape|csv_?safe|safe_?csv|["']=\+-@|["']=["']\s*,\s*["']\+["']|\[=\+\\?-@|\^\[=`, content)

# Both are judged on code with comment lines removed: a Javadoc that says
# "text/csv" is not a download, and "# TODO: sanitise" is not a sanitiser.
_gate(path, content) if {
	not helpers.is_test_path(path)
	code := regex.replace(content, `(?m)^[ \t]*(?://|#|/?\*).*$`, "")
	_http_csv(code)
	not _sanitised(code)
}

# ── Python ──────────────────────────────────────────────────────────────

_py_literal_row := `^\[\s*(?:(?:"[^"]*"|'[^']*')\s*,?\s*)*\]\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`csv\.(?:writer|DictWriter)\(|\.to_csv\(`, content)
	_gate(path, content)
	lines := split(content, "\n")
	writers := {w |
		some l in lines
		regex.match(`csv\.(?:writer|DictWriter)\(`, l)
		w := helpers.assigned_first(l)
	}
	some i, line in lines
	regex.match(`\.writerows?\(|\.to_csv\(`, line)
	not helpers.is_comment_line(line)
	_py_sink(line, writers)
	finding := _finding(path, i, line)
}

_py_sink(line, writers) if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.writerows?\(\s*(.*)$`, line, 1)
	count(m) > 0
	m[0][1] in writers
	not regex.match(_py_literal_row, m[0][2])
}

_py_sink(line, _) if regex.match(`\b\w+\.to_csv\(`, line)

# ── JavaScript / TypeScript ─────────────────────────────────────────────

_is_js(path) if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_js_libs := `['"](?:json2csv|@json2csv/[\w-]+|csv-stringify(?:/sync)?|fast-csv|@fast-csv/format|papaparse|objects-to-csv)['"]`

_js_sink_re := `new\s+(?:json2csv\.)?Parser\s*\([^;]*\)\.parse\(|\bjson2csv\.parse\(|(?:^|[^.\w])stringify\(|\bcsv\.stringify\(|\bPapa\.unparse\(|\bcsv\.(?:write|writeToStream|writeToString|writeToBuffer|format)\(|(?:^|[^.\w])writeToStream\(|(?:^|[^.\w])writeToString\(`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(_js_libs, content)
	_gate(path, content)
	lines := split(content, "\n")
	parsers := {p |
		some l in lines
		regex.match(`=\s*new\s+(?:json2csv\.)?Parser\s*\(`, l)
		p := helpers.assigned_first(l)
	}
	some i, line in lines
	regex.match(`parse\(|stringify\(|unparse\(|csv\.|writeTo`, line)
	not helpers.is_comment_line(line)
	_js_sink(line, parsers)
	finding := _finding(path, i, line)
}

_js_sink(line, _) if regex.match(_js_sink_re, line)

_js_sink(line, parsers) if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_$][\w$]*)\.parse\(`, line, 1)
	count(m) > 0
	m[0][1] in parsers
}

# ── Java ────────────────────────────────────────────────────────────────

_java_literal_row := `^new\s+String\s*\[\s*\]\s*\{\s*(?:"[^"]*"\s*,?\s*)*\}\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`CSVWriter|CSVPrinter`, content)
	_gate(path, content)
	lines := split(content, "\n")
	writers := {w |
		some l in lines
		regex.match(`=\s*(?:new\s+(?:CSVWriter|CSVPrinter|CSVWriterBuilder)\b|CSVFormat\.[\w.()]*\bprint(?:er)?\()`, l)
		w := helpers.assigned_ident(l)
	}
	some i, line in lines
	regex.match(`\.(?:writeNext|writeAll|printRecords?)\(`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.(?:writeNext|writeAll|printRecords?)\(\s*(.*)$`, line, 1)
	count(m) > 0
	m[0][1] in writers
	not regex.match(_java_literal_row, m[0][2])
	finding := _finding(path, i, line)
}
