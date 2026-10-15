# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1007",
	"name": "Mixed-script homoglyph in source code",
	"description": "A word in Python, JavaScript/TypeScript or Java source mixes ASCII Latin letters with a Cyrillic or Greek letter that renders like a Latin one (Cyrillic а е о р с у х і ј ѕ ԁ and capitals А В Е К М Н О Р С Т Х, Greek Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ ο ν ρ α), directly or as a \\uXXXX escape beside a Latin letter. Such a word reads as an ordinary name to a reviewer and a user but compares unequal to it: \"аdmin\" with a Cyrillic а passes a check against \"admin\", a spoofed domain such as \"pаypal.com\" looks genuine, and an identifier spelled that way shadows the real one (the homoglyph form of Trojan Source). Not reported: text written wholly in Cyrillic or Greek, Greek letters used as symbols (Δ, μ, Ω, π), comments, and test files (which legitimately hold homoglyph samples). The rule reads source text only; it does not judge whether a user interface renders IDN domains or usernames distinguishably.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1007/",
	"languages": ["java", "node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1007],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["homoglyphs", "unicode", "spoofing", "cwe-1007"],
}

_confusable := `[АВЕКМНОРСТХаеорсухіјѕԁӏЅІЈΑΒΕΖΗΙΚΜΝΟΡΤΥΧονρα]`

_esc := `\\u0(?:4[0-5][0-9a-fA-F]|3[9abcABC][0-9a-fA-F])`

_mixed := concat("", [`[A-Za-z]`, _confusable, `|`, _confusable, `[A-Za-z]|(?:^|[^\\A-Za-z])[A-Za-z]+`, _esc, `|`, _esc, `[A-Za-z]`])

_ext(path) if regex.match(`\.(?:py|js|jsx|mjs|cjs|ts|tsx|java)$`, path)

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	not helpers.is_test_path(path)
	regex.match(`[\x{0370}-\x{04FF}]|\\u0[34]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_mixed, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:#|//)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Word mixes Latin letters with a Cyrillic or Greek lookalike: it reads as an ordinary name but compares unequal to it, the shape used to spoof usernames, domains and identifiers. Spell it in one script, or normalise and reject mixed-script input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
