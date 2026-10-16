# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1322

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1322",
	"name": "Use of Blocking Code in Single-threaded, Non-blocking Context",
	"description": "A synchronous, event-loop-blocking Node.js API (fs.*Sync such as readFileSync/writeFileSync/readdirSync/statSync/existsSync, child_process execSync/execFileSync/spawnSync, crypto pbkdf2Sync/scryptSync/generateKeyPairSync, zlib gzipSync/inflateSync and friends, bcrypt hashSync/compareSync) is called inside an HTTP request handler: a function taking (req, res), (request, reply|response|h) or a Koa ctx, including http.createServer callbacks. While it runs, the single-threaded server answers no other request, so one slow disk, process or key derivation (or an attacker who triggers it repeatedly) stalls every client. Not reported: sync calls at module level or in helpers outside a handler (startup, cache warm-up), the asynchronous and promise APIs, build scripts and CLIs, test files, comments and string literals. A sync call reached from a handler through a helper function in another place is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1322/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1322],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["blocking-in-non-blocking", "event-loop", "dos", "cwe-1322"],
}

_exts := {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}

# A blocking call: a Sync method on a module that does I/O or heavy CPU, or a
# destructured import of one of those functions.
_sync_re := `(?:\b(?:fs|fse|fsExtra|fsSync|nodeFs|child_process|childProcess|cp|crypto|zlib|bcrypt|bcryptjs)\.[a-zA-Z0-9]+Sync\s*\(|(?:^|[^\w.$])(?:readFileSync|writeFileSync|appendFileSync|readdirSync|statSync|lstatSync|existsSync|mkdirSync|copyFileSync|unlinkSync|rmSync|rmdirSync|renameSync|accessSync|openSync|readSync|writeSync|execSync|execFileSync|spawnSync|pbkdf2Sync|scryptSync|generateKeyPairSync|gzipSync|gunzipSync|inflateSync|deflateSync|brotliCompressSync|brotliDecompressSync|hashSync|compareSync)\s*\()`

# The header of a request handler.
_handler_re := `(?:\(\s*|\bfunction\s*[\w$]*\s*\(\s*)_?(?:req|request)\s*(?::\s*[\w.]+(?:<.*?>)?(?:\[\])?)?\s*,\s*(?:res|response|reply|h)\b|\basync\s*(?:\(\s*ctx\b|ctx\s*=>)|\bfunction\s*[\w$]*\s*\(\s*ctx\s*[,)]|^\s*@(?:Get|Post|Put|Patch|Delete|All|Head|Options)\s*\(`

_indent(l) := count(l) - count(trim_left(l, " \t"))

# Remove string and template literals so prose about a Sync API is not code.
_strip(l) := regex.replace(l, concat("", [`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`, "`[^`]*`"]), `""`)

# The handler header and the blocking call on one line, header first.
_in_handler(_, _, code) if {
	regex.match(concat("", [`(?:`, _handler_re, `).*(?:`, _sync_re, `)`]), code)
}

# A handler header above, at a shallower indent, whose block is still open.
_in_handler(lines, i, _) if {
	i > 0
	ii := _indent(lines[i])
	some j in numbers.range(max([0, i - 60]), i - 1)
	regex.match(_handler_re, lines[j])
	not helpers.is_comment_line(lines[j])
	ij := _indent(lines[j])
	ij < ii
	not _closed(lines, j, i, ij)
}

_closed(lines, j, i, ij) if {
	j + 1 <= i - 1
	some m in helpers.span(j + 1, i - 1)
	_indent(lines[m]) <= ij
	regex.match(`^\s*[})\]]`, lines[m])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	contains(content, "Sync")
	regex.match(_sync_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Sync")
	not helpers.is_comment_line(line)
	code := _strip(line)
	regex.match(_sync_re, code)
	_in_handler(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "Synchronous (blocking) API called inside a request handler: it stalls the event loop for every client. Use the async or promise form (fs.promises, child_process.execFile with a callback, crypto.pbkdf2, zlib.gzip)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
