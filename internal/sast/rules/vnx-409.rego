# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_409

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-409",
	"name": "Improper Handling of Highly Compressed Data (Data Amplification)",
	"description": "Reports decompression whose output size is not bounded, so a small compressed input (a zip or gzip bomb) expands until memory or disk runs out. Python: `extractall()` or a per-member `extract()` on a zipfile.ZipFile (bound with `with ... as zf`, assigned, or chained) in a file that never reads a member's `file_size`; `extractall()` on a tarfile.open(...) archive in a file that never reads a member `.size`; `shutil.unpack_archive(...)`; and gzip/zlib/bz2/lzma `.decompress(x)` (module aliases included) where x is read from the request (Flask/Django request.data/body/files/get_data/stream), a socket recv or an HTTP response, on the line or assigned in the 15 lines above. Node/TypeScript: zlib `gunzip`, `inflate`, `inflateRaw`, `unzip`, `brotliDecompress` and their Sync forms called without `maxOutputLength` in the call (up to 5 lines), `req/res.pipe(zlib.createGunzip())`-style streams from a request or response, adm-zip `extractAllTo` in a file that never reads `header.size`, `unzipper.Extract(...)`, and `unzipper.Open.buffer/file/url(...)` in a file whose entries are streamed out and that never reads `uncompressedSize`. Not reported: `zlib.decompressobj().decompress(data, max)`, decompression of local or constant data in Python, string-literal arguments, compression calls, test files, comments and strings. Ratio checks written in other ways and limits enforced in another file are not recognised.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-409/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [409],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["data-amplification", "cwe-409"],
}

_strip(l) := regex.replace(l, concat("", [`"(\\.|[^"\\])*"|'(\\.|[^'\\])*'|`, "`[^`]*`"]), `""`)

_js_file(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx)$`, path)

_report(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Python ───────────────────────────────────────────────────────────────

_py_zip_msg := "extract()/extractall() writes members of this zip archive without checking its uncompressed size: a zip bomb of a few kilobytes can fill the disk. Sum info.file_size over infolist() and reject archives over a limit before extracting."

# A zip opened with `with ZipFile(...) as v` or `v = ZipFile(...)` above.
_py_zip_bound(lines, i, v) if {
	some k in numbers.range(max([0, i - 40]), i - 1)
	l := lines[k]
	contains(l, "ZipFile(")
	regex.match(concat("", [`\bZipFile\(.*\bas\s+`, v, `\s*:|\b`, v, `\s*=\s*(zipfile\.)?ZipFile\(`]), l)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "ZipFile")
	contains(content, ".extract")
	lines := split(content, "\n")
	not regex.match(`\bfile_size\b`, helpers.code_text(lines))
	some i, line in lines
	contains(line, ".extract")
	not helpers.is_comment_line(line)
	code := _strip(line)
	_py_zip_extract(lines, i, code)
	finding := _report(path, i, line, _py_zip_msg)
}

_py_zip_extract(_, _, code) if regex.match(`\bZipFile\([^#]*\)\.extract(all)?\(`, code)

_py_zip_extract(lines, i, code) if {
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.extract(?:all)?\(`, code, -1)
	_py_zip_bound(lines, i, m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "unpack_archive(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "unpack_archive(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	regex.match(`(^|[^\w.]|\bshutil\.)unpack_archive\(`, code)
	not regex.match(`\bdef\s+unpack_archive\(`, code)
	finding := _report(path, i, line, "shutil.unpack_archive() extracts every member with no limit on the uncompressed size, so a compressed bomb fills the disk. Open the archive with zipfile/tarfile, check each member's size and the total, then extract.")
}

_py_src := `\brequest\.(data|body|files|FILES|get_data|stream|read)\b|\.recv\(|\burlopen\(|\brequests\.(get|post|put|request)\(|\b(httpx|session)\.(get|post|request)\(`

# Module names and their `import zlib as z` aliases.
_py_mods(content) := {"gzip", "zlib", "bz2", "lzma"} | {m[2] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+(gzip|zlib|bz2|lzma)\s+as\s+(\w+)`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, ".decompress(")
	mods := _py_mods(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".decompress(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	some m in regex.find_all_string_submatch_n(`\b(\w+)\.decompress\(\s*([^,)]*(?:\([^()]*\))?[^,)]*)\s*\)`, code, -1)
	m[1] in mods
	_py_tainted(m[2], lines, i)
	finding := _report(path, i, line, sprintf("%s.decompress() expands request or network data with no limit on the output size: a small compressed body can exhaust memory. Use zlib.decompressobj() and decompress(data, max_length), rejecting input whose output exceeds the limit.", [m[1]]))
}

_py_tainted(arg, _, _) if regex.match(_py_src, arg)

_py_tainted(arg, lines, i) if {
	some v in helpers.tainted_names(lines, i, 15, _py_src)
	regex.match(concat("", [`\b`, v, `\b`]), arg)
}

# ── Node / TypeScript ────────────────────────────────────────────────────

_zlib_fns := `gunzip|inflate|inflateRaw|unzip|brotliDecompress`

# The call text from line i, at most 5 lines.
_call(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 4]))])

# Bare names count only when destructured from the zlib module.
_js_bare_ok(content, fn) if {
	regex.match(concat("", [`\{[^}]*\b`, fn, `\b[^}]*\}\s*(=\s*require\(\s*['"](node:)?zlib['"]|from\s*['"](node:)?zlib['"])`]), content)
}

_js_zlib_call(content, code) := fn if {
	m := regex.find_all_string_submatch_n(concat("", [`(^|[^\w.]|\bzlib\.)((?:`, _zlib_fns, `)(?:Sync)?)\(\s*([^\s)]|$)`]), code, 1)
	count(m) > 0
	fn := m[0][2]
	not m[0][3] in {`"`, `'`, "`"}
	_js_qualified(content, m[0][1], fn)
}

_js_qualified(_, "zlib.", _)

_js_qualified(content, pre, fn) if {
	pre != "zlib."
	_js_bare_ok(content, fn)
}

findings contains finding if {
	some path, content in input.file_contents
	_js_file(path)
	not helpers.is_test_path(path)
	contains(content, "zlib")
	regex.match(concat("", [`(`, _zlib_fns, `)(Sync)?\(`]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(concat("", [`(`, _zlib_fns, `)(Sync)?\(`]), line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	not regex.match(`\bfunction\s+\w+\s*\(`, code)
	fn := _js_zlib_call(content, code)
	not contains(_call(lines, i), "maxOutputLength")
	finding := _report(path, i, line, sprintf("zlib %s() is called without maxOutputLength, so the decompressed size is unbounded and a small compressed input can exhaust memory. Pass { maxOutputLength: <limit> }.", [fn]))
}

findings contains finding if {
	some path, content in input.file_contents
	_js_file(path)
	not helpers.is_test_path(path)
	contains(content, "zlib.create")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "pipe(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	regex.match(`\b(req|request|res|resp|response|ctx\.req)\s*\.pipe\(\s*zlib\.create(Gunzip|Inflate|InflateRaw|Unzip|BrotliDecompress)\(\s*\)`, code)
	finding := _report(path, i, line, "A request or response stream is piped through a zlib decompressor with no limit on the bytes it produces: a compressed bomb expands without bound. Count the output bytes in a Transform and destroy the stream past a limit.")
}

findings contains finding if {
	some path, content in input.file_contents
	_js_file(path)
	not helpers.is_test_path(path)
	contains(content, "adm-zip")
	contains(content, "extractAllTo")
	lines := split(content, "\n")
	not contains(helpers.code_text(lines), "header.size")
	some i, line in lines
	contains(line, "extractAllTo")
	not helpers.is_comment_line(line)
	regex.match(`\b\w+\.extractAllTo(Async)?\(`, _strip(line))
	finding := _report(path, i, line, "adm-zip extractAllTo() writes every entry without checking its uncompressed size (entry.header.size), so a zip bomb fills the disk. Sum the entry sizes from getEntries() and reject archives over a limit first.")
}

findings contains finding if {
	some path, content in input.file_contents
	_js_file(path)
	not helpers.is_test_path(path)
	contains(content, "unzipper")
	not contains(content, "uncompressedSize")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "unzipper.Extract(")
	not helpers.is_comment_line(line)
	contains(_strip(line), "unzipper.Extract(")
	finding := _report(path, i, line, "unzipper.Extract() writes every entry without a size limit, so a zip bomb fills the disk. Parse entries with unzipper.Parse(), check entry.vars.uncompressedSize and stop past a limit.")
}

# tarfile: the same unbounded extraction. A tar member's size is `.size`;
# a file that reads any `<member>.size` is taken to check it.
_py_tar_bound(lines, i, v) if {
	some k in numbers.range(max([0, i - 40]), i - 1)
	l := lines[k]
	contains(l, "open(")
	regex.match(concat("", [`\btarfile\.open\(.*\bas\s+`, v, `\s*:|\b`, v, `\s*=\s*tarfile\.open\(`]), l)
}

_py_tar_extract(_, _, code) if regex.match(`\btarfile\.open\([^#]*\)\.extractall\(`, code)

_py_tar_extract(lines, i, code) if {
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.extractall\(`, code, -1)
	_py_tar_bound(lines, i, m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "tarfile.open(")
	contains(content, "extractall(")
	lines := split(content, "\n")
	not regex.match(`\b\w+\.size\b`, helpers.code_text(lines))
	some i, line in lines
	contains(line, "extractall(")
	not helpers.is_comment_line(line)
	code := _strip(line)
	_py_tar_extract(lines, i, code)
	finding := _report(path, i, line, "extractall() writes every member of this tar archive without checking its size: a compressed tar bomb can fill the disk. Sum member.size over getmembers() and reject archives over a limit before extracting.")
}

# unzipper.Open.buffer/file/url(...): the entries are then streamed out
# (entry.stream() / entry.buffer()) with no look at their uncompressed size.
findings contains finding if {
	some path, content in input.file_contents
	_js_file(path)
	not helpers.is_test_path(path)
	contains(content, "unzipper.Open.")
	not contains(content, "uncompressedSize")
	regex.match(`\.(stream|buffer)\(\s*\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "unzipper.Open.")
	not helpers.is_comment_line(line)
	regex.match(`\bunzipper\.Open\.(buffer|file|url|s3|s3_v3|custom)\(`, _strip(line))
	finding := _report(path, i, line, "The entries of this unzipper archive are read out without checking entry.vars.uncompressedSize, so a zip bomb expands without bound. Check each entry's uncompressed size and the running total before streaming it.")
}
