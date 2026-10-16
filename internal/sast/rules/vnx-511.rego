# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_511

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-511",
	"name": "Logic/Time Bomb: destructive action gated on a hard-coded date",
	"description": "A time bomb: a condition that compares the current time with a hard-coded date and, in the block it guards (the same line or the indented lines below, up to eight), deletes files or directories, runs a shell command or evaluates code. The current time is read on the condition line or through a variable assigned only the current time within ten lines above (now = datetime.now(timezone.utc); const today = new Date()). Python: datetime.now()/utcnow()/today() (with or without a time zone), date.today() or time.time() compared with datetime(20xx, ...)/date(20xx, ...), a string that is a 20xx-mm-dd date, a .year against 20xx or a 10-digit epoch, guarding os.remove/unlink/rmdir/removedirs, shutil.rmtree, os.system/popen, subprocess, exec/eval or os.kill. JavaScript/TypeScript: Date.now() or new Date() (also .getFullYear()) compared with new Date('20xx...')/new Date(20xx, ...), Date.parse('20xx...'), a 13-digit epoch or a constant assigned such a date in the file, guarding fs.rm/rmSync/unlink/unlinkSync/rmdir/rmdirSync/writeFileSync (also on fs.promises or an fs alias, and await rm()/unlink()), child_process exec/execSync/execFile/spawn/fork (bare or on a cp/child/childProcess receiver), eval, process.kill or rimraf. Not reported: a file whose name merely contains a date (\"2024-01-01.log\"), date checks that only warn, log, raise or return (deprecation notices, certificate expiry), age comparisons with no fixed date (time.time() - mtime > MAX_AGE), and code in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-511/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [511],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["logic-time-bomb", "malicious-code", "cwe-511"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
	endswith(path, ext)
}

_now := {
	"py": `\b(?:datetime\.(?:now|utcnow|today)|date\.today|time\.time)\s*\(\s*(?:(?:tz\s*=\s*)?[\w.]+\s*)?\)`,
	"js": `\bDate\.now\s*\(\s*\)|\bnew\s+Date\s*\(\s*\)`,
}

_literal := {
	"py": `\b(?:datetime|date)\s*\(\s*20\d\d\s*,|["']20\d\d-\d\d-\d\d(?:[T ][\d:.]*(?:Z|[+-]\d\d:?\d\d)?)?["']|\.year\s*(?:[<>]=?|==)\s*20\d\d\b|(?:[<>]=?|==)\s*1[5-9]\d{8}(?:\.\d+)?\b`,
	"js": `\bnew\s+Date\s*\(\s*(?:["'\x60]20\d\d|20\d\d\s*,)|\bDate\.(?:parse|UTC)\s*\(\s*(?:["']20\d\d|20\d\d\s*,)|getFullYear\s*\(\s*\)\s*(?:[<>]=?|===?)\s*20\d\d\b|(?:[<>]=?|===?)\s*1[5-9]\d{11}\b`,
}

_payload := {
	"py": `\bos\.(?:remove|unlink|rmdir|removedirs|system|popen|kill)\s*\(|\bshutil\.rmtree\s*\(|\bsubprocess\.\w+\s*\(|(?:^|[^\w.])(?:exec|eval)\s*\(`,
	"js": `\bfs\w*(?:\.promises)?\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|writeFileSync)\s*\(|\bawait\s+(?:rm|unlink|rmdir)\s*\(|\b(?:cp|child|childProcess|proc)\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(|(?:^|[^\w.$])(?:exec|execSync|spawn|spawnSync)\s*\(|child_process\w*\.\w+\s*\(|(?:^|[^\w.$])eval\s*\(|\bprocess\.kill\s*\(|\brimraf\s*\(`,
}

_gate("py", content) if {
	regex.match(_now.py, content)
	regex.match(`os\.|shutil\.|subprocess|exec\(|eval\(`, content)
}

_gate("js", content) if {
	regex.match(_now.js, content)
	regex.match(`fs|exec|spawn|eval\(|process\.kill|rimraf|\brm\(`, content)
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# Names assigned a hard-coded date anywhere in the file:
# const CUTOFF = new Date("2026-12-31").
_date_consts(lang, lines) := {v |
	some l in lines
	regex.match(_literal[lang], l)
	not regex.match(`^\s*(?:if|elif|while)\b`, l)
	not helpers.is_comment_line(l)
	v := helpers.assigned_ident(l)
}

# Variables holding the current time and nothing else, assigned within ten
# lines above: now = datetime.now(timezone.utc); const today = new Date();
_now_vars(lang, lines, i) := {m[1] |
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	contains(l, "=")
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:(?:const|let|var)\s+)?(\w+)\s*(?::\s*\w+\s*)?=\s*(?:`, _now[lang], `)\s*;?\s*$`]), l, 1)[0]
}

# The condition reads the current time, by the call itself or through a
# variable holding it. The value is the prefix the payload must follow.
_reads_now(lang, line, _) := concat("", [`^.*?(?:`, _now[lang], `)`]) if regex.match(_now[lang], line)

_reads_now(lang, line, vars) := concat("", [`^.*?\b`, v, `\b`]) if {
	not regex.match(_now[lang], line)
	some v in vars
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

_condition(lang, line, consts) if regex.match(_literal[lang], line)

_condition(lang, line, consts) if {
	some v in consts
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The block the condition guards: the lines below it indented deeper than
# it, at most eight. The first line at its own depth or shallower ends it.
_block_end(lines, i) := e if {
	ind := _indent(lines[i])
	last := min([count(lines) - 1, i + 8])
	ends := [k |
		some k in numbers.range(i + 1, last)
		trim_space(lines[k]) != ""
		_indent(lines[k]) <= ind
	]
	e := min(array.concat([last + 1], ends))
}

# On the condition's own line, after the time it reads.
_destructive(lang, lines, i, c, prefix) if {
	regex.match(_payload[lang], regex.replace(c, prefix, ""))
}

_destructive(lang, lines, i, _, _) if {
	e := _block_end(lines, i)
	e - 1 >= i + 1
	some k in helpers.span(i + 1, e - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_payload[lang], _code(l))
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	lines := split(content, "\n")
	consts := _date_consts(lang, lines)
	some i, line in lines
	contains(line, "if")
	regex.match(`^\s*(?:\}\s*else\s+)?(?:if|elif)\b`, line)
	prefix := _reads_now(lang, line, _now_vars(lang, lines, i))
	_condition(lang, line, consts)
	_destructive(lang, lines, i, _code(line), prefix)
	finding := {
		"rule_id": metadata.id,
		"message": "A destructive action runs only after a hard-coded date: this is the shape of a time bomb. Remove the date trigger or justify it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
