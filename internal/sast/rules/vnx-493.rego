# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_493

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-493",
	"name": "Critical Public Variable Without Final Modifier",
	"description": "A public field that any code can overwrite holds security- or business-critical data: in Java a public field without final, in C# a public field without readonly or const, whose name says it is a password, passphrase, secret, API key, private key, token, credential, an admin flag, role, permission or privilege, or a price, balance, amount or salary. Any class can change it, so a check that reads it can be steered. Static and instance fields are both reported. Not reported: final, readonly and const fields, C# properties ({ get; ... } or =>), private, protected and package-private fields (package scope is VNX-487), constants that name a parameter or header rather than hold the value, methods, test code, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-493/",
	"languages": ["java", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [493],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["critical-public-variable", "final", "readonly", "cwe-493"],
}

# public (in any modifier order), a type, a name, then = or ;. No parentheses
# before the name, so a method is never a field.
_field_re := `^\s*((?:(?:public|static|volatile|transient|final|readonly|const|internal|new|unsafe)\s+)+)[A-Za-z_][\w.]*(?:<[^;=()]*>)?\??(?:\s*\[\])*\s+([A-Za-z_]\w*)\s*(?:=[^=>]|;)`

_critical_re := `(?i)password|passwd|passphrase|secret|api_?key|private_?key|token|credential|^is_?admin|admin$|^role|role$|^roles$|permission|privilege|price|balance|amount|salary`

_label_name_re := `(?:_(?i:params?|parameters?|fields?|headers?|attrs?|attributes?|label|names?|prefix|suffix|pattern|regex|url|uri|path|length|len|min|max|size|type|kind|placeholder|hint|prompt|keyname|property|prop|env|var|column|col|msg|message|error|cookie|query|endpoint|format)|[a-z0-9](?:Params?|Parameters?|Fields?|Headers?|Attrs?|Attributes?|Label|Names?|Prefix|Suffix|Pattern|Regex|Url|Uri|URL|URI|Path|Length|Len|Min|Max|Size|Type|Kind|Placeholder|Hint|Prompt|Property|Prop|Env|Var|Column|Col|Msg|Message|Error|Cookie|Query|Endpoint|Format))$`

_exts := {".java", ".cs"}

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not helpers.is_test_path(path)
	contains(content, "public")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "public")
	not helpers.is_comment_line(line)
	c := _code(line)
	m := regex.find_all_string_submatch_n(_field_re, c, 1)
	count(m) > 0
	mods := m[0][1]
	regex.match(`\bpublic\b`, mods)
	not regex.match(`\b(?:final|readonly|const)\b`, mods)
	name := m[0][2]
	regex.match(_critical_re, name)
	not regex.match(_label_name_re, name)
	not regex.match(`(?i)tokeni[sz]|secretar`, name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Critical field '%s' is public and not final/readonly: any code can overwrite it. Make it private (or final/readonly) and expose a read-only accessor", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
