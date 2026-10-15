# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_363

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-363",
	"name": "Race condition enabling link following (symlink check, then open by name)",
	"description": "A path is tested for being a symbolic link and then opened, written or re-permissioned by name a few lines later. The test and the use are two lookups, so a local attacker can swap a regular file for a link to /etc/passwd or a key file between them, and the program follows it. Reported, with the use on the same path within ten lines of the check: Python os.path.islink(p) or p.is_symlink() then open(p), os.open(p) without O_NOFOLLOW, os.chmod/os.chown, shutil.copy*(p) or a pathlib p.open/read/write/chmod; Go os.Lstat(p) whose result is tested against os.ModeSymlink then os.Create/Open/OpenFile/ReadFile/WriteFile/Chmod/Chown(p); Java Files.isSymbolicLink(p) then a java.nio.file.Files read, write or open of p without LinkOption.NOFOLLOW_LINKS, or new FileOutputStream/FileWriter/FileInputStream/RandomAccessFile(p or p.toFile()); Node fs.lstat/lstatSync(p) tested with isSymbolicLink() then an fs read, write, open, chmod or chown of p without O_NOFOLLOW; PHP is_link($p) then fopen, file_put_contents, file_get_contents, readfile, chmod, chown, touch or copy of $p; Ruby File.symlink?(p) then File/IO.open, read, write, chmod or chown of p. A use whose call wraps over lines is read as one statement. Not reported: an open with O_NOFOLLOW or NOFOLLOW_LINKS (also on a continuation line of the call), a use of a different path, os.readlink/readlinkSync (reading the link itself), unlink of the link, a check and use through a directory handle (os.Root, openat), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-363/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [363],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["race-condition", "symlink", "toctou", "cwe-363"],
}

_window := 10

_id := `([A-Za-z_][\w\.]*)`

_php_id := `(\$[A-Za-z_]\w*)`

# Per language: the extensions, a whole-file gate, the link checks (with a
# confirming test that must follow within four lines when the check API
# itself does not say "link"), and the uses that follow a link.
_langs := {
	"python": {
		"exts": [".py"],
		"gate": `os\.path\.islink\(|\.is_symlink\(\)`,
		"checks": [
			{"re": concat("", [`\bos\.path\.islink\(\s*`, _id, `\s*\)`]), "confirm": ""},
			{"re": concat("", [`\b`, _id, `\.is_symlink\(\)`]), "confirm": ""},
		],
		"uses": [
			concat("", [`(?:^|[^\w\.])open\(\s*`, _id, `\s*[,\)]`]),
			concat("", [`\b(?:os|io)\.open\(\s*`, _id, `\s*[,\)]`]),
			concat("", [`\bos\.(?:chmod|chown|truncate)\(\s*`, _id, `\s*,`]),
			concat("", [`\bshutil\.(?:copy|copy2|copyfile|copyfileobj)\(\s*`, _id, `\s*,`]),
			concat("", [`\b`, _id, `\.(?:open|read_text|read_bytes|write_text|write_bytes|chmod)\(`]),
		],
		"nofollow": `O_NOFOLLOW|follow_symlinks\s*=\s*False`,
	},
	"go": {
		"exts": [".go"],
		"gate": `ModeSymlink`,
		"checks": [{"re": concat("", [`\bos\.Lstat\(\s*`, _id, `\s*\)`]), "confirm": `ModeSymlink`}],
		"uses": [concat("", [`\b(?:os|ioutil)\.(?:Create|Open|OpenFile|ReadFile|WriteFile|Chmod|Chown|Truncate)\(\s*`, _id, `\s*[,\)]`])],
		"nofollow": `O_NOFOLLOW`,
	},
	"java": {
		"exts": [".java"],
		"gate": `isSymbolicLink\(`,
		"checks": [{"re": concat("", [`\bFiles\.isSymbolicLink\(\s*`, _id, `\s*\)`]), "confirm": ""}],
		"uses": [
			concat("", [`\bFiles\.(?:write|writeString|newOutputStream|newBufferedWriter|newByteChannel|newInputStream|newBufferedReader|readAllBytes|readAllLines|readString|lines|setPosixFilePermissions|setOwner|copy)\(\s*`, _id, `\s*[,\)]`]),
			concat("", [`\bnew\s+(?:FileOutputStream|FileWriter|FileInputStream|FileReader|RandomAccessFile|PrintWriter)\(\s*([A-Za-z_]\w*)(?:\.toFile\(\))?\s*[,\)]`]),
		],
		"nofollow": `NOFOLLOW_LINKS`,
	},
	"node": {
		"exts": [".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"],
		"gate": `isSymbolicLink\(\)`,
		"checks": [{"re": concat("", [`\blstat(?:Sync)?\(\s*`, _id, `\s*[,\)]`]), "confirm": `isSymbolicLink\(\)`}],
		"uses": [concat("", [`\.(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|createReadStream|readFileSync|readFile|chmodSync|chmod|chownSync|chown|openSync|open|truncateSync|truncate|copyFileSync|copyFile)\(\s*`, _id, `\s*[,\)]`])],
		"nofollow": `O_NOFOLLOW`,
	},
	"php": {
		"exts": [".php"],
		"gate": `is_link\(`,
		"checks": [{"re": concat("", [`\bis_link\(\s*`, _php_id, `\s*\)`]), "confirm": ""}],
		"uses": [concat("", [`\b(?:fopen|file_put_contents|file_get_contents|readfile|file|chmod|chown|chgrp|touch|copy)\(\s*`, _php_id, `\s*[,\)]`])],
		"nofollow": `O_NOFOLLOW`,
	},
	"ruby": {
		"exts": [".rb"],
		"gate": `symlink\?`,
		"checks": [
			{"re": concat("", [`\bFile\.symlink\?\(\s*`, _id, `\s*\)`]), "confirm": ""},
			{"re": concat("", [`\bFile\.lstat\(\s*`, _id, `\s*\)\.symlink\?`]), "confirm": ""},
		],
		"uses": [
			concat("", [`\b(?:File|IO)\.(?:open|read|write|binread|binwrite|readlines|foreach|truncate)\(\s*`, _id, `\s*[,\)]`]),
			concat("", [`\bFile\.(?:chmod|chown)\([^,\n]*,\s*`, _id, `\s*\)`]),
		],
		"nofollow": `NOFOLLOW`,
	},
}

_lang_of(path) := l if {
	some l, cfg in _langs
	some e in cfg.exts
	endswith(path, e)
}

# Long string literals are prose, not code. Short ones (a mode "w") stay.
_code(line) := regex.replace(line, `"(?:[^"\\\n]|\\.){6,}"|'(?:[^'\\\n]|\\.){6,}'`, `""`)

# The statement that starts on line i: the line itself, or up to two more
# lines while its parentheses are still open (a call wrapped over lines, whose
# path or NOFOLLOW option sits on a continuation line).
_open_parens(t) if count(indexof_n(t, "(")) > count(indexof_n(t, ")"))

_stmt(lines, i) := lines[i] if not _open_parens(lines[i])

_stmt(lines, i) := t if {
	_open_parens(lines[i])
	t := concat(" ", array.slice(lines, i, i + 2))
	not _open_parens(t)
}

_stmt(lines, i) := concat(" ", array.slice(lines, i, i + 3)) if {
	_open_parens(lines[i])
	_open_parens(concat(" ", array.slice(lines, i, i + 2)))
}

_checked(lines, i, cfg, target) if {
	some j in numbers.range(max([0, i - _window]), i)
	l := lines[j]
	not helpers.is_comment_line(l)
	some chk in cfg.checks
	some m in regex.find_all_string_submatch_n(chk.re, _code(l), -1)
	m[1] == target
	_confirmed(lines, j, chk.confirm)
}

_confirmed(_, _, "") := true

_confirmed(lines, j, re) if {
	re != ""
	some k in numbers.range(j, min([count(lines) - 1, j + 4]))
	regex.match(re, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang_of(path)
	cfg := _langs[lang]
	regex.match(cfg.gate, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _code(_stmt(lines, i))
	not regex.match(cfg.nofollow, code)
	some re in cfg.uses
	some m in regex.find_all_string_submatch_n(re, code, -1)
	target := m[1]
	_checked(lines, i, cfg, target)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is tested for being a symlink and then opened by name: the file can be replaced with a link between the test and the use. Open it once without following links (O_NOFOLLOW, LinkOption.NOFOLLOW_LINKS, openat in a trusted directory) and check the open handle", [target]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
