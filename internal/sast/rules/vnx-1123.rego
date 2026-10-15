# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1123

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1123",
	"name": "Excessive Use of Self-Modifying Code",
	"description": "Code that rewrites itself at run time. Python: a program opening its own source for writing (open(__file__, sys.argv[0] or os.path.abspath/realpath of either, \"w\"/\"a\"/\"r+\"/\"x\", or mode= keyword), Path(__file__).write_text/write_bytes/open(\"w\"), or os.open(__file__, O_WRONLY/O_RDWR)), replacing a function's bytecode (fn.__code__ = ...), and building or patching code objects (types.CodeType(...), code.replace(co_code=...)). JavaScript/TypeScript: fs.writeFile/writeFileSync/appendFile/appendFileSync/createWriteStream on __filename, process.argv[1], import.meta.filename, fileURLToPath(import.meta.url) or new URL(import.meta.url). A call wrapped after its opening parenthesis is read with the next two lines. Self-modifying code defeats review, signing and integrity checks, and is a common trait of droppers and persistence implants. Not reported: reading one's own source (open(__file__, \"rb\"), the usual test-fixture idiom), exec(compile(open(path).read(), path, \"exec\")) of another file (setup.py version loading, which is not self-modification), writes to other paths, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1123/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1123],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["self-modifying-code", "cwe-1123"],
}

_self_py := `(?:__file__|sys\.argv\[0\]|os\.path\.(?:abspath|realpath)\(\s*(?:__file__|sys\.argv\[0\])\s*\))`

_py_patterns := [
	{
		"re": concat("", [`\b(?:io\.|codecs\.)?open\(\s*`, _self_py, `\s*,\s*(?:mode\s*=\s*)?[rbuU]?["'][rbt]*[wax+][a-z+]*["']`]),
		"msg": "Program opens its own source file for writing",
	},
	{
		"re": concat("", [`\b(?:io\.|codecs\.)?open\(\s*`, _self_py, `\s*,[^)]*\bmode\s*=\s*["'][rbt]*[wax+]`]),
		"msg": "Program opens its own source file for writing",
	},
	{
		"re": concat("", [`Path\(\s*`, _self_py, `\s*\)(?:\.resolve\(\))?\.(?:write_(?:text|bytes)\(|open\(\s*(?:mode\s*=\s*)?["'][rbt]*[wax+])`]),
		"msg": "Program overwrites its own source file",
	},
	{
		"re": concat("", [`\bos\.open\(\s*`, _self_py, `\s*,[^)]*\bO_(?:WRONLY|RDWR|APPEND|TRUNC)\b`]),
		"msg": "Program opens its own source file for writing",
	},
	{
		"re": `\.__code__\s*=[^=]`,
		"msg": "Function bytecode replaced at run time (__code__ assignment)",
	},
	{
		"re": `\b(?:types\.)?CodeType\(|\.replace\([^)]*\bco_code\s*=`,
		"msg": "Code object constructed or patched at run time",
	},
]

_js_re := `\b(?:fs\.|fsp\.|promises\.)?(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\(\s*(?:__filename|process\.argv\[1\]|import\.meta\.filename|fileURLToPath\(\s*import\.meta\.url\s*\)|new\s+URL\(\s*import\.meta\.url\s*\))\s*[,)]`

# Remove string literals so a pattern quoted in a log message or docstring is
# not code. Mode strings are checked on the raw line by the open patterns,
# which anchor on the call itself.
_unquoted(line) := regex.replace(line, concat("", [`"[^"]*"|'[^']*'|`, "`[^`]*`"]), `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`__file__|sys\.argv\[0\]|__code__|CodeType|co_code`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`__file__|argv|__code__|CodeType|co_code|\bopen\(\s*$`, raw)
	not helpers.is_comment_line(raw)
	line := _logical(lines, i, raw)
	some p in _py_patterns
	regex.match(p.re, line)
	_code_mentions(line)
	finding := {
		"rule_id": metadata.id,
		"message": p.msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# A call broken after its opening parenthesis (open(\n __file__, "w"),
# code.replace(\n co_code=...)) is read together with the next two lines.
_logical(_, _, raw) := raw if not regex.match(`\(\s*$`, raw)

_logical(lines, i, raw) := concat(" ", array.slice(lines, i, i + 3)) if regex.match(`\(\s*$`, raw)

# The self-reference or code-object name must survive string removal, so
# `log("open(__file__, 'w')")` is not code.
_code_mentions(line) if regex.match(`__file__|sys\.argv\[0\]|__code__|CodeType|co_code`, _unquoted(line))

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(js|mjs|cjs|ts|mts|cts)$`, path)
	regex.match(`__filename|process\.argv\[1\]|import\.meta`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`writeFile|appendFile|createWriteStream`, line)
	not helpers.is_comment_line(line)
	regex.match(_js_re, _unquoted(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Script writes to its own source file",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
