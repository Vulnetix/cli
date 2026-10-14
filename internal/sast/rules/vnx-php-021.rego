package vulnetix.rules.vnx_php_021

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-021",
	"name": "Laravel mass assignment via empty guarded array",
	"description": "Laravel Eloquent mass-assignment protection is switched off: a class property $guarded is declared as an empty array (protected/public $guarded = [], [ ], array(), or [ on one line and ] on the next), or Model::unguard() / Eloquent::unguard() / static::unguard() is called (with no argument or true) in application code that never calls reguard(). Any attribute, including is_admin, role or password, can then be set through create(), fill() or update() with request data. Not reported: a non-empty $guarded list (['id'], ['*']) or a $fillable allowlist, a local variable named $guarded, Model::unguarded(fn) (scoped to a callback), unguard() followed by reguard() in the same file, unguard(false), seeders, factories and migrations under database/, pivot models (extends Pivot/MorphPivot, filled by attach()), the framework's own and vendored package models (Illuminate/, vendor/), test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-021/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-77"],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["mass-assignment", "laravel", "eloquent", "php"],
}

_prop := `^\s*(?:(?:public|protected|private|var|static)\s+)+(?:\??array\s+)?\$guarded\s*=\s*`

_empty_re := concat("", [_prop, `(?:\[\s*\]|array\s*\(\s*\))\s*;`])

_open_re := concat("", [_prop, `(?:\[|array\s*\()\s*$`])

_unguard_re := `(^|[^\w$>\\])(?:Model|Eloquent|static|self|\\?Illuminate\\Database\\Eloquent\\Model)::unguard\s*\(\s*(?:true\s*)?\)`

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)database/(seeders|seeds|factories|migrations)/`, path)

# Framework and vendored package models are filled by their own code with
# attributes the package chooses (Pivot, DatabaseNotification).
_skip(path) if regex.match(`(^|/)(vendor|Illuminate)/`, path)

_empty_guarded(_, _, line) if regex.match(_empty_re, line)

_empty_guarded(lines, i, line) if {
	regex.match(_open_re, line)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(`^\s*[\])]\s*;`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "$guarded")
	not _skip(path)
	not regex.match(`\bextends\s+\\?(?:[\w\\]+\\)?(?:Pivot|MorphPivot)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "$guarded")
	_empty_guarded(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "$guarded = [] disables mass-assignment protection for this Eloquent model, so request data can set any column (is_admin, role, password); declare $fillable with the attributes that may be mass-assigned",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "::unguard")
	not contains(content, "::reguard")
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "::unguard")
	not helpers.is_comment_line(line)
	regex.match(_unguard_re, _no_strings(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Model::unguard() disables mass-assignment protection for every Eloquent model and is never re-enabled here; remove it (or scope it with Model::unguarded(fn)) and define $fillable on each model",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
