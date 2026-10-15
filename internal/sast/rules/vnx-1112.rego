# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1112

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1112",
	"name": "Incomplete Documentation of Program Execution",
	"description": "A Python command-line option or argument that changes how the program runs but is missing from its --help text: an argparse '.add_argument(...)' or optparse '.add_option(...)' call (including Django management commands and subparsers) or a '@click.option(...)' decorator with no 'help=' keyword anywhere in the call, which may span several lines. Reported at the line that opens the call. Not reported: calls that pass 'help=' (including help=argparse.SUPPRESS, a deliberate choice to hide an option), calls that expand '**options' (help may be inside), action='version' and action='help' (argparse supplies their help text), an add_option call whose first argument is not a '-' flag or dest= (a menu or config API, not optparse), calls inside a triple-quoted string (a usage example in a docstring), add_argument_group/add_mutually_exclusive_group, click.argument (which takes no help), commented-out calls, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1112/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1112],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incomplete-execution-docs", "cli", "cwe-1112"],
}

_call_re := `^\s*(?:@\s*click\.option\s*\(|@\s*[A-Za-z_]\w*\.option\s*\(|[A-Za-z_][\w\.\]\[]*\.add_(?:argument|option)\s*\()`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\.add_(?:argument|option)\s*\(|click\.option\s*\(|\.option\s*\(`, content)
	not helpers.is_test_path(path)
	_cli_module(content)
	lines := split(content, "\n")
	quotes := _quote_lines(content, lines)
	some i, line in lines
	contains(line, "(")
	regex.match(_call_re, line)
	call := _call_text(lines, i)
	not regex.match(`\bhelp\s*=`, call)
	not regex.match(`[(,]\s*\*\*\s*[A-Za-z_]`, call)
	not regex.match(`\baction\s*=\s*["'](?:version|help)["']`, call)
	not _not_optparse(call)
	not _in_string(quotes, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Command-line option has no help= text, so --help does not document how it changes the program's execution",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_cli_module(content) if contains(content, "argparse")

_cli_module(content) if contains(content, "optparse")

_cli_module(content) if contains(content, "add_arguments(")

_cli_module(content) if contains(content, "import click")

_cli_module(content) if contains(content, "from click")

# the call's text from its opening line until its parentheses balance
_call_text(lines, i) := s if {
	end := min([count(lines) - 1, i + 20])
	ks := [k |
		some k in numbers.range(i, end)
		t := concat("\n", array.slice(lines, i, k + 1))
		count(indexof_n(t, "(")) <= count(indexof_n(t, ")"))
	]
	count(ks) > 0
	s := concat("\n", array.slice(lines, i, ks[0] + 1))
}

# unbalanced to the window's end: judge the window
_call_text(lines, i) := s if {
	end := min([count(lines) - 1, i + 20])
	not _balances(lines, i, end)
	s := concat("\n", array.slice(lines, i, end + 1))
}

_balances(lines, i, end) if {
	some k in numbers.range(i, end)
	t := concat("\n", array.slice(lines, i, k + 1))
	count(indexof_n(t, "(")) <= count(indexof_n(t, ")"))
}

# optparse options are named by their flags; another library's add_option (a menu, a config) is not
_not_optparse(call) if {
	regex.match(`\.add_option\s*\(`, call)
	not regex.match(`\.add_option\s*\(\s*(?:["']-|dest\s*=)`, call)
}

# lines holding triple quotes, with how many, to tell when a line sits inside a docstring
_quote_lines(content, lines) := [] if {
	not contains(content, `"""`)
	not contains(content, "'''")
}

_quote_lines(content, lines) := qs if {
	regex.match(`"""|'''`, content)
	qs := [[k, n] |
		some k, l in lines
		regex.match(`"""|'''`, l)
		n := count(regex.find_n(`"""|'''`, l, -1))
	]
}

_in_string(quotes, i) if {
	n := sum([q[1] | some q in quotes; q[0] < i])
	n % 2 == 1
}
