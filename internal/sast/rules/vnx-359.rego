# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_359

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-359",
	"name": "Private personal information written to logs or standard output",
	"description": "A value that identifies a person (social security number, passport number, date of birth, national ID or national insurance number, tax ID, driver's licence number, medical record number) is passed to a logging call or printed, so it lands in log files, log shippers and support tooling that people without a need to know can read. Reported in Python (logging/logger/log/app.logger calls, logging.getLogger(...).info(...) chains, print), JavaScript/TypeScript (console.*, logger/log/winston/pino/bunyan/req.log calls) and Java (log/logger/LOG/LOGGER and LoggerFactory.getLogger(...) calls, System.out/err.print*): a call whose arguments, followed across up to four continuation lines and including f-string and template-literal interpolations, name such a value as an identifier, property, getter, object key or subscript/get key (applicant.ssn, customer.getSsn(), dateOfBirth, passport_number, { ssn }, data[\"ssn\"], payload.get(\"dob\")). Each argument is judged on its own, so a hashed argument does not excuse a raw one beside it. Not reported: the words inside a string literal (\"Collecting SSN\"), lookalike names (has_passport, dobVerified, ssnMasked), a bare passport in a JavaScript file that imports Passport.js (the authentication library), arguments that are masked, redacted, hashed, encrypted, truncated to the last four ([-4:], .slice(-4)) or reduced to a null/presence check (!= null, is not None, !!x, bool(), Boolean(), len(), .length, isPresent()), comments, and test files. Credentials and card numbers in logs are VNX-NODE-031 and VNX-GO-040.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-359/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [359],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["pii-exposure", "logging", "privacy", "cwe-359"],
}

_lang(path) if regex.match(`\.(py|js|mjs|cjs|jsx|ts|tsx|mts|cts|java)$`, path)

_file_gate := `(?:^|[^A-Za-z])(?i:ssn|dob|mrn)|[a-z](?:Ssn|SSN|Dob|DOB|Mrn|MRN)|(?i:social_?security|passport|birth|national_?(?:id|insurance)|tax_?id|drivers?_?licen[cs]e|medical_?record)`

_gate(c) if contains(c, "ssn")

_gate(c) if contains(c, "Ssn")

_gate(c) if contains(c, "SSN")

_gate(c) if contains(c, "ocialSecurity")

_gate(c) if contains(c, "ocial_security")

_gate(c) if contains(c, "assport")

_gate(c) if contains(c, "irth")

_gate(c) if contains(c, "dob")

_gate(c) if contains(c, "Dob")

_gate(c) if contains(c, "DOB")

_gate(c) if contains(c, "ationalId")

_gate(c) if contains(c, "ational_id")

_gate(c) if contains(c, "ationalInsurance")

_gate(c) if contains(c, "ational_insurance")

_gate(c) if contains(c, "axId")

_gate(c) if contains(c, "ax_id")

_gate(c) if contains(c, "icenseNumber")

_gate(c) if contains(c, "icense_number")

_gate(c) if contains(c, "ersLicense")

_gate(c) if contains(c, "ers_license")

_gate(c) if contains(c, "edicalRecord")

_gate(c) if contains(c, "edical_record")

_gate(c) if contains(c, "mrn")

_log_call := `(?:\b(?:logging|logger|log|_log|_logger|LOG|LOGGER|Log|winston|pino|bunyan)|\b(?:logging|LoggerFactory|Logger|LogManager)\s*\.\s*get(?:Logger|Log)\s*\([^()]*\)|\bself\.(?:logger|log)|\b(?:current_)?app\.logger|\bthis\.(?:logger|log)|\breq\.log|\bfastify\.log)\s*\.\s*(?:debug|info|warning|warn|error|exception|critical|fatal|trace|verbose|silly|severe|fine|log)\s*\(|\bconsole\s*\.\s*(?:log|info|warn|error|debug|trace)\s*\(|(?:^|[^\w.])print\s*\(|\bSystem\s*\.\s*(?:out|err)\s*\.\s*print(?:ln|f)?\s*\(`

_pii_token := `^(?:get)?(?:(?:user|customer|client|applicant|patient|person|member|employee|holder|owner|primary|raw|plain|full|their|my)_?)?(?:ssn|socialsecurity(?:number|no|num)?|passport(?:number|no|num|id)?|dateofbirth|birthdate|dob|nationalid(?:number|no)?|nationalinsurance(?:number|no)?|taxid(?:number|no)?|drivers?licen[cs]e(?:number|no|num)?|medicalrecord(?:number|no)?|mrn)$`


# The arguments with every safe sub-expression removed, so one masked or
# presence-checked argument does not excuse a raw one beside it.
_neutral_res := [
	# a call to a masking, hashing, encrypting or presence function (one nested call allowed)
	`[\w.$]*(?i:mask|redact|anonymi|obfuscat|hash|sha\d*|md5|encrypt|digest|last_?4|last_?four|truncat|bool|boolean|len|isset|empty)\w*\s*\((?:[^()]|\([^()]*\))*\)`,
	# presence checks
	`!!\s*[\w.$]+(?:\(\))?`,
	`[\w.$]+(?:\([^()]*\))?\s*[!=]==?\s*(?:null|undefined|None|nil)\b`,
	`[\w.$]+\s+is\s+(?:not\s+)?None\b`,
	`[\w.$]+(?:\(\))?\.(?:length|isPresent\(\)|isEmpty\(\)|isBlank\(\))`,
	# last four characters only
	`[\w.$]+(?:\(\))?\s*(?:\[\s*-\s*4\s*:\s*\]|\.slice\(\s*-\s*4\s*\)|\.substr(?:ing)?\(\s*-\s*4\s*\)|\.substring\([^()]*length(?:\(\))?\s*-\s*4[^()]*\))`,
]

_neutral(s) := regex.replace(regex.replace(regex.replace(regex.replace(regex.replace(regex.replace(s, _neutral_res[0], " "), _neutral_res[1], " "), _neutral_res[2], " "), _neutral_res[3], " "), _neutral_res[4], " "), _neutral_res[5], " ")

_strip(s) :=regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\x60[^\x60]*\x60`, `""`)

_interps(s) := concat(" ", [m[1] | some m in regex.find_all_string_submatch_n(`\{([^{}]*)\}`, s, -1)])

_parens(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# The call on line i with its continuation lines, until the parentheses balance (at most 5 lines).
_call(lines, i) := concat("\n", array.slice(lines, i, i + n)) if {
	end := min([count(lines), i + 5])
	stops := [k |
		some k in numbers.range(i, end - 1)
		_parens(_strip(concat("\n", array.slice(lines, i, k + 1)))) <= 0
	]
	n := _first_or(stops, end - 1) - i + 1
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	_gate(content)
	regex.match(_file_gate, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")

	# only lines up to four above one that names a PII value can start the call
	cand := {k |
		some j, l in lines
		_gate(l)
		regex.match(_file_gate, l)
		some k in numbers.range(max([0, j - 4]), j)
	}
	some i in cand
	line := lines[i]
	contains(line, "(")
	regex.match(`(?i)log|print|console|pino|winston|bunyan`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_log_call, line, 1)
	count(m) > 0

	# cheap: the five lines the call may span name a PII value at all
	regex.match(_file_gate, concat("\n", array.slice(lines, i, i + 5)))
	text := _call(lines, i)
	regex.match(_file_gate, text)
	args := _neutral(substring(text, indexof(text, m[0][0]), -1))
	code := _drop_passport_lib(path, content, concat(" ", [_strip(args), _interps(args)]))
	ident_toks := {t |
		some m in regex.find_all_string_submatch_n(`[A-Za-z_$][\w$]*`, code, -1)
		t := m[0]
		regex.match(_pii_token, lower(replace(t, "_", "")))
	}

	# data["ssn"], data.get("ssn"), map.get("passportNumber")
	key_toks := {t |
		some m in regex.find_all_string_submatch_n(`(?:\[\s*|\.get\(\s*)["']([A-Za-z_]\w*)["']`, args, -1)
		t := m[1]
		regex.match(_pii_token, lower(replace(t, "_", "")))
	}
	toks := ident_toks | key_toks
	count(toks) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Personal data (%s) is written to a log or standard output, where people without a need to know can read it. Log a record id instead, or mask the value", [concat(", ", sort(toks))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# In a JavaScript file that imports Passport.js, a bare `passport` is the
# authentication library, not a passport number (traveller.passport still is).
_passport_lib_re := `(?:require\(\s*["']passport["']\s*\)|from\s+["']passport["']|import\s+\*?\s*(?:as\s+)?passport\b)`

_drop_passport_lib(path, content, code) := regex.replace(code, `(^|[^.\w$])passport\b`, "$1 ") if {
	not endswith(path, ".py")
	not endswith(path, ".java")
	regex.match(_passport_lib_re, content)
}

_drop_passport_lib(path, content, code) := code if endswith(path, ".py")

_drop_passport_lib(path, content, code) := code if endswith(path, ".java")

_drop_passport_lib(path, content, code) := code if {
	not endswith(path, ".py")
	not endswith(path, ".java")
	not regex.match(_passport_lib_re, content)
}
