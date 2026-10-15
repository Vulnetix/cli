# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_233

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-233",
	"name": "Improper Handling of Parameters",
	"description": "Request parameters are forwarded wholesale as keyword arguments, so every extra or undefined parameter a client sends is accepted: Python ** unpacking of a Flask/Django/DRF request mapping (request.GET, POST, args, form, values, json, get_json(), data, query_params, params, with or without .dict()/.to_dict()/.copy()) into a call or dict literal, inline or through a variable assigned from one in the ten lines above. Into an ORM filter() this lets a client add lookups such as password__startswith; into a constructor, create() or update() it sets fields the form never offered (is_admin, owner). Not reported: explicit keyword arguments, a dict built by a comprehension that filters keys, serializer.validated_data and form.cleaned_data, **kwargs in a def, exponentiation, the text in comments and string literals, and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-233/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [233],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-handling-of-parameters", "cwe-233", "mass-assignment"],
}

_mapping := `request\.(?:GET|POST|args|form|values|json|get_json|data|query_params|params)\b`

_splat_prefix := `(?:^\s*|[(,{]\s*)\*\*\s*`

_inline_re := concat("", [_splat_prefix, `(?:self\.)?`, _mapping])

_code(line) := c if {
	a := regex.replace(line, `(^|[^fFrRbB\w"'])"(?:[^"\\]|\\.)*"`, `$1""`)
	c := regex.replace(a, `(^|[^fFrRbB\w"'])'(?:[^'\\]|\\.)*'`, `$1''`)
}

# Names assigned from a request mapping (not from a filtering comprehension)
# in the ten lines above i.
_tainted(lines, i) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	j < i
	prev := lines[j]
	regex.match(_mapping, prev)
	not helpers.is_comment_line(prev)
	not regex.match(`\bfor\b`, prev)
	regex.match(concat("", [`=\s*(?:self\.)?`, _mapping, `(?:\.(?:dict|to_dict|copy)\(\))?(?:\([^()]*\))?(?:\s+or\s+(?:\{\s*\}|dict\(\)))?\s*(?:#.*)?$`]), prev)
	v := helpers.assigned_first(prev)
}

_hit(_, _, code) if regex.match(_inline_re, code)

_hit(lines, i, code) if {
	some v in _tainted(lines, i)
	regex.match(concat("", [_splat_prefix, v, `\b`]), code)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "**")
	contains(content, "request.")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "**")
	not startswith(trim_space(line), "#")
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
	code := _code(line)
	_hit(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "Request parameters are unpacked as keyword arguments, so any extra parameter the client sends is accepted (ORM lookups, privileged fields). Pass an explicit list of fields or validated data",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
