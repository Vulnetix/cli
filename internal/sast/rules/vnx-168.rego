# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_168

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-168",
	"name": "Improper Handling of Inconsistent Special Elements",
	"description": "CSV is parsed by splitting each line on every comma, which ignores CSV quoting: a comma inside a quoted field (\"Smith, John\") is treated the same as a field separator, so columns shift and a value lands in the wrong field (role, amount, email). Reported: Python/JavaScript/TypeScript/Java .split(\",\") (also the regex spellings /,/ and \"\\\\s*,\\\\s*\", re.split and a chained .split(\",\") on a continuation line), Go strings.Split/SplitN(x, \",\"), and PHP explode(\",\", ...) and preg_split('/,/', ...) within 25 code lines of a CSV reference (.csv, text/csv, a csv-named variable or upload field such as contacts_csv) in a file that uses no CSV parser (Python csv/pandas, papaparse/csv-parse/csv-parser/fast-csv/d3-dsv, OpenCSV/Commons CSV/Jackson CSV/univocity, Go encoding/csv, PHP fgetcsv/str_getcsv/League\\Csv). Not reported: comma-separated values that are not CSV (headers, environment variables, tag lists) away from any CSV reference, a comma list read from configuration (process.env, os.environ/getenv, System.getenv, config./settings. objects) or from a request parameter (req.query/req.body, request.args/form, $_GET/$_POST, FormValue, getParameter) even next to CSV code, a split of a string literal, files that parse CSV with a library, comments and string literals, test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-168/",
	"languages": ["python", "node", "java", "go", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [168],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["inconsistent-special-element", "csv", "parsing", "cwe-168"],
}

_ext_ok := {"py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "go", "php"}

# A comma separator, also the regex spellings (Java "\\s*,\\s*", JS /,/,
# re.split / preg_split), a chained ".split(" that starts a continuation line,
# Go strings.Split / SplitN, and PHP explode.
_split_re := `(?:(?:^\s*|[\w\)\]]\s*)\.split\(\s*(?:","|',')\s*(?:,\s*-?\d+\s*)?\)|(?:^\s*|[\w\)\]]\s*)\.split\(\s*(?:["'](?:\\\\s[*+])?\s*,\s*(?:\\\\s[*+])?["']|/(?:\\s[*+])?,(?:\\s[*+])?/[gimsuy]*)\s*[,)]|\bre\.split\(\s*r?["'](?:\\s[*+])?,(?:\\s[*+])?["']\s*,|\bpreg_split\(\s*['"]/(?:\\s[*+])?,(?:\\s[*+])?/[a-z]*['"]\s*,|\bstrings\.SplitN?\(\s*[^,"']+,\s*","\s*[,)]|\bexplode\(\s*(?:","|',')\s*,)`

# The comma list comes from configuration (an env var, a settings object),
# which is a list of options, not a CSV record.
_config_source(line) if regex.match(`process\.env\b|\bos\.environ\b|\bgetenv\(|\bSystem\.getenv\(|\b(?:config|settings|conf|cfg|options|opts)\.[\w.]+\.split\(|\benv\(`, line)

# So is a command-line flag or argument: strings.Split(*labels, ","), a Go
# flag pointer; sys.argv, process.argv, os.Args, argparse's args.x, cobra's
# GetString. A flag whose help text mentions a .csv file is still a flag.
_config_source(line) if regex.match(`\bstrings\.SplitN?\(\s*\*[A-Za-z_]\w*\s*,|\bflag\.\w+\(|\bos\.Args\b|\bsys\.argv\b|\bprocess\.argv\b|\bargs\.[\w.]+\.split\(|\.GetString(?:Slice)?\(|\bargv\[`, line)

# A comma list read from a request parameter (?fields=id,name, a form value)
# is a list of options, not a CSV record, even beside a CSV export.
_param_source(line) if regex.match(`\breq\.(?:query|body|params)\b|\brequest\.(?:args|form|GET|POST|query_params|values)\b|\$_(?:GET|POST|REQUEST)\b|\.FormValue\(|\.URL\.Query\(\)|\.getParameter\(|\.query\.get\(|searchParams\.get\(`, line)

_parser_re :=`\bimport\s+csv\b|\bfrom\s+csv\s+import|\bpandas\b|read_csv|papaparse|Papa\.parse|csv-parse|csv-parser|fast-csv|d3-dsv|csvtojson|CSVReader|CSVParser|CSVFormat|opencsv|univocity|CsvMapper|"encoding/csv"|fgetcsv|str_getcsv|League\\Csv|READ_CSV`

# What says the text is a CSV document rather than a comma-separated
# parameter: a .csv name, the CSV media type, a csv file/row/upload name.
_csv_context := `(?i)\.csv\b|text/csv|csv_?(?:file|path|line|lines|row|rows|data|text|content|upload|reader|export|import)|['"]csv['"]|[a-z0-9]_csv\b`

_split_word(l) if contains(l, "split(")

_split_word(l) if contains(l, "Split")

_split_word(l) if contains(l, "explode(")

_csv_mention(c) if contains(c, ".csv")

_csv_mention(c) if contains(c, ".CSV")

_csv_mention(c) if contains(c, "csv")

_csv_mention(c) if contains(c, "Csv")

_csv_mention(c) if contains(c, "CSV")

_in_string(line, word) if {
	idx := indexof(line, word)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	count(regex.find_n(`"`, pre, -1)) % 2 == 1
}

_in_string(line, word) if {
	idx := indexof(line, word)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	count(regex.find_n(`'`, pre, -1)) % 2 == 1
}

_src[path] := content if {
	some path, content in input.file_contents
	parts := split(path, ".")
	_ext_ok[parts[count(parts) - 1]]
	not helpers.is_test_path(path)
	not contains(path, ".min.")
}

findings contains finding if {
	some path, content in _src
	_csv_mention(content)
	contains(content, ",")
	not regex.match(_parser_re, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 1000
	contains(line, ",")
	_split_word(line)
	regex.match(_split_re, line)
	not helpers.is_comment_line(line)
	not _config_source(line)
	not _param_source(line)
	some call in regex.find_n(`[Ss]plit(?:N)?\(|explode\(`, line, 1)
	not _in_string(line, call)
	regex.match(_csv_context, helpers.code_window(lines, i, 25, 25))
	finding := {
		"rule_id": metadata.id,
		"message": "CSV split on every comma ignores quoting: a quoted field containing a comma shifts every later column. Parse CSV with a CSV parser (csv module, encoding/csv, fgetcsv, papaparse, Commons CSV)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
