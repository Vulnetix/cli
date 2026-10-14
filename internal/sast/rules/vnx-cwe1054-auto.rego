# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1054

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1054",
	"name": "Invokable Control Element with Excessive Volume of Commented-out Code",
	"description": "A block of line comments in Go, Java, JavaScript/TypeScript, PHP, Python or Ruby that is disabled code rather than prose: at least three of its lines read as code (a statement terminator with a keyword, assignment or call; a Python block opener ending in ':'; a closing brace; a bare return/break/raise; an unterminated assignment; in Ruby a bare 'end', a condition on a method call, or a DSL call with a symbol such as before_action :authenticate_user!). Disabled code can hold old credentials, bypassed security checks or deprecated algorithms that a developer might re-enable. One finding per block, at its first code-like line. Not reported: prose (six lower-case words in a row, or a line that is not code-like), a single commented-out line, usage examples in documentation comments (a code-like line indented deeper than the prose of the same block, as in RDoc, godoc and Javadoc), godoc preformatted lines (a tab after //), block comments (/* */), test files, and library code under node_modules/vendor/dist or JavaScript copied into static/assets/public trees.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1054/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1054],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["comments", "commented-code", "dead-code", "code-quality", "secrets-in-comments", "cwe-1054"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

_skip(path) if endswith(path, ".min.css")

# extension → the line-comment marker of that language
_marker := {
	".go": "//",
	".java": "//",
	".js": "//",
	".jsx": "//",
	".ts": "//",
	".tsx": "//",
	".mjs": "//",
	".php": "//",
	".py": "#",
	".rb": "#",
}

# The text of a line comment, or undefined when the line is not one. `#!` and
# `#include`/`#define`/`#if` are not comments of this kind.
_comment_text(line, "//") := t if {
	m := regex.find_all_string_submatch_n(`^\s*//+[ ]?([^\t ].*|[ ]+\S.*|)$`, line, 1)
	count(m) > 0
	t := trim_space(m[0][1])
}

_comment_text(line, "#") := t if {
	m := regex.find_all_string_submatch_n(`^\s*#\s?(.*)$`, line, 1)
	count(m) > 0
	t := trim_space(m[0][1])
	not startswith(t, "!")
}

# A comment line reads as code when it ends the way a statement ends and
# starts or contains the way one does. Prose ends in a full stop or runs on
# into the next line; six lower-case words in a row is a sentence.
_code_like(t) if {
	regex.match(`(\{|\}|;|\))\s*$`, t)
	regex.match(`^(if|for|while|switch|return|var|let|const|func|def|import|require|try|catch|else|defer|go)\b|[\w\]\)]\s*(:=|==|!=|\+=|-=|=)\s*\S|^[\w\.]+\(`, t)
	not regex.match(`\b[a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,}\b`, t)
}

_code_like(t) if {
	regex.match(`^(if|for|while|elif|else|def|class|try|except|with)\b.*:\s*$`, t)
	not regex.match(`\b[a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,}\b`, t)
}

_is_comment(lines, j, marker) if {
	_comment_text(lines[j], marker)
}

# Index of the first line after i that is not a comment of this style, looking
# at most _window lines ahead. Scanning to the end of the file for every block
# was quadratic: a large, heavily commented bundle took minutes. A block longer
# than the window still reports, at its start.
_window := 40

_block_end(lines, i, marker) := e if {
	last := min([i + _window, count(lines) - 1])
	ends := {j |
		some j in numbers.range(i, last)
		not _is_comment(lines, j, marker)
	}
	count(ends) > 0
	e := min(ends)
}

_block_end(lines, i, marker) := e if {
	last := min([i + _window, count(lines) - 1])
	ends := {j |
		some j in numbers.range(i, last)
		not _is_comment(lines, j, marker)
	}
	count(ends) == 0
	e := last + 1
}

# Library code copied into a static asset tree is not the project's own.
_skip(path) if regex.match(`(^|/)(node_modules|bower_components|vendor|third_party|dist|build)/`, path)

_skip(path) if regex.match(`(^|/)(static|assets|public|wwwroot)/.*\.js$`, path)

_skip(path) if regex.match(`(^|/)(jquery|three|bootstrap|lodash|angular|ace)[\w.-]*\.js$`, path)

# Spaces between the comment marker and the text, beyond the usual one.
_inner(line) := count(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`^\s*(?://+|#)( *)`, line, 1)
	count(m) > 0
}

# A comment block that also holds prose is documentation; a code-like line
# indented deeper than the prose is a usage example in it (RDoc, godoc,
# Javadoc pre blocks), not disabled code.
_has_prose(lines, block, marker, base) if {
	some j in block
	_inner(lines[j]) <= base
	t := _comment_text(lines[j], marker)
	not startswith(t, "//")
	not startswith(t, "#")
	not _code_like(t)
	regex.match(`[A-Za-z]{2,}[,']?\s+[A-Za-z]{2,}\s+[A-Za-z]{2,}`, t)
}

_prose(lines, block, marker, base) := true if {
	_has_prose(lines, block, marker, base)
} else := false

_counts(false, _, _)

_counts(true, n, base) if n <= base

findings contains finding if {
	some path, content in input.file_contents
	not _skip(path)
	not helpers.is_test_path(path)
	some ext, marker in _marker
	endswith(path, ext)
	lines := split(content, "\n")
	some i, line in lines
	_is_comment(lines, i, marker)
	# the first line of a block, not every line of one
	_block_start(lines, i, marker)
	e := _block_end(lines, i, marker)
	block := numbers.range(i, e - 1)
	base := min([_inner(lines[j]) | some j in block; _comment_text(lines[j], marker) != ""])
	prose := _prose(lines, block, marker, base)
	code_lines := [j |
		some j in block
		_code_like(_comment_text(lines[j], marker))
		_counts(prose, _inner(lines[j]), base)
	]
	count(code_lines) >= 3
	finding := {
		"rule_id": metadata.id,
		"message": "Block of commented-out code; it may hold old credentials, bypassed security checks or deprecated logic. Remove it rather than leaving it commented out",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": code_lines[0] + 1,
		"snippet": lines[code_lines[0]],
	}
}

_block_start(_, 0, _)

_block_start(lines, i, marker) if {
	i > 0
	not _is_comment(lines, i - 1, marker)
}

# Structural lines of a disabled block: a closing brace, a bare return, and an
# assignment or call that carries no terminator (Python and Ruby have none).
_code_like(t) if regex.match(`^[\}\)\]]+[;,]?\s*(else\b.*)?$`, t)

_code_like(t) if regex.match(`^(return|break|continue|pass|raise)\b(\s+[\w\.\(\)"']+){0,2}\s*;?$`, t)

_code_like(t) if {
	regex.match(`^[A-Za-z_][\w\.\[\]]*\s*(:=|\+=|-=|=)\s*[^=\s]`, t)
	not regex.match(`\b[a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,} [a-z]{2,}\b`, t)
}

# Ruby: a bare `end`, a condition on a method call or ivar, and a DSL call
# with a symbol argument (before_action :authenticate_user!)
_code_like(t) if t == "end"

_code_like(t) if regex.match(`^(if|unless|elsif|while|until)\s+!?[@\w]*[._@?!(]\S*(\s+(&&|\|\|)\s+\S+)?$`, t)

_code_like(t) if regex.match(`^[a-z_]+\s+:[a-z_]\w*[!?]?(,\s*[\w:]+(\s*(=>|:)\s*\S+)?)*$`, t)
