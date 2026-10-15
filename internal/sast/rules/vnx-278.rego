# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_278

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-278",
	"name": "Insecure Preserved Inherited Permissions",
	"description": "Files are extracted from an archive with the permissions (and in some cases the owner) the archive carries, so a world-writable, setuid or attacker-owned entry keeps those properties on disk without anyone deciding it should. Reported: libarchive extraction with ARCHIVE_EXTRACT_PERM, ARCHIVE_EXTRACT_OWNER or ARCHIVE_EXTRACT_ACL set unconditionally, including in a #define'd flag set (C, C++); Python tarfile extract()/extractall() with no filter argument, filter=None or filter=\"fully_trusted\" (before Python 3.14 the default keeps every mode bit, including setuid and group/other write), on a name or attribute (self.archive) bound to tarfile.open() (also through an `import tarfile as` alias) or a parameter annotated tarfile.TarFile, and shutil.unpack_archive() without a filter; Go archive/tar and archive/zip extractors that create or chmod files with the entry's own mode (os.FileMode(hdr.Mode), hdr.FileInfo().Mode(), info.Mode() after info := hdr.FileInfo(), a zip entry's f.Mode(), directly or through a variable) or chown them to the entry's Uid/Gid; and the Rust tar crate's Archive::set_preserve_permissions(true) and set_preserve_ownerships(true). Not reported: the flags set only under a user option (an if/else/case/switch on the same or the previous line or around the block, ?:, as with tar -p), a flag tested with & rather than set, a tarfile filter of \"data\" or \"tar\" or a module-wide extraction_filter, zipfile and zip archives given to unpack_archive (which do not restore modes), a mode masked with a constant (&0o755, &^0o022, also on the mode variable before the call), the tar crate's defaults and set_preserve_*(false), test code, and the names in comments or strings. Path traversal in the same calls is a separate weakness and is not judged here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-278/",
	"languages": ["c", "cpp", "python", "go", "rust"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [278],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["preserved-inherited-permissions", "archive-extraction", "file-permissions", "cwe-278"],
}

_msg := "Archive entries are extracted with the permissions they carry: a world-writable, setuid or foreign-owned entry keeps those bits on disk. Apply your own mode instead (libarchive without ARCHIVE_EXTRACT_PERM/OWNER, tarfile filter=\"data\", a masked mode in Go)"

_strip(line) := regex.replace(line, `"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`, `""`)

_prev_code(lines, i) := lines[k] if {
	i > 0
	ks := [j | some j in numbers.range(max([0, i - 3]), i - 1); trim_space(lines[j]) != ""; not helpers.is_comment_line(lines[j])]
	count(ks) > 0
	k := ks[count(ks) - 1]
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# ── C / C++: libarchive ──────────────────────────────────────────────────

_c_ext(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

# Set only when the user asked for it (tar -p): an if, a case label or a
# conditional expression decides.
_user_option(line, _) if regex.match(`\bif\s*\(|\?`, line)

_user_option(_, lines_i) if regex.match(`\bif\s*\(|\bcase\b.*:|\belse\b`, lines_i)

_indent(l) := count(l) - count(trim_left(l, " \t"))

# The previous code line, or "" at the top of a file: a plain object.get
# over an undefined value would make the whole rule body undefined.
_prev_or_empty(lines, i) := p if p := _prev_code(lines, i)

else := ""

# The statement sits in a block opened by an if/else/case/switch
# (`if (opt_same_perms) {` / Allman `if (root)` + `{`): the nearest code line
# above that is indented less, skipping a lone `{`.
_in_conditional_block(lines, i) if {
	i > 0
	ind := _indent(lines[i])
	outer := [j |
		some j in numbers.range(max([0, i - 30]), i - 1)
		t := trim_space(lines[j])
		t != ""
		t != "{"
		not helpers.is_comment_line(lines[j])
		_indent(lines[j]) < ind
	]
	count(outer) > 0
	regex.match(`\bif\s*\(|\belse\b|\bcase\b.*:|\bdefault\s*:|\bswitch\s*\(`, lines[outer[count(outer) - 1]])
}

# Code, not comments; a #define is code here (a flag set defined once and
# passed to archive_write_disk_set_options), unless it defines the
# ARCHIVE_EXTRACT_ constant itself.
_c_code_line(line) if not helpers.is_comment_line(line)

_c_code_line(line) if {
	regex.match(`^\s*#\s*define\s`, line)
	not regex.match(`^\s*#\s*define\s+ARCHIVE_EXTRACT_\w+`, line)
}

findings contains finding if {
	some path, content in input.file_contents
	_c_ext(path)
	contains(content, "ARCHIVE_EXTRACT_")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ARCHIVE_EXTRACT_")
	_c_code_line(line)
	code := _strip(line)
	regex.match(`(^|[^~\w])\s*ARCHIVE_EXTRACT_(PERM|OWNER|ACL)\b`, code)
	not regex.match(`~\s*\(?\s*ARCHIVE_EXTRACT_(PERM|OWNER|ACL)\b`, code)
	# `flags & ARCHIVE_EXTRACT_PERM` tests the flag, it does not set it.
	not regex.match(`(^|[^&])&\s*\(?\s*ARCHIVE_EXTRACT_(PERM|OWNER|ACL)\b`, code)
	not _user_option(code, _prev_or_empty(lines, i))
	not _in_conditional_block(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Python: tarfile and shutil.unpack_archive ────────────────────────────

# The names the tarfile module goes by in this file: `tarfile`, and the alias
# of `import tarfile as tf`.
_tar_mods(lines) := {"tarfile"} | {m[1] |
	some l in lines
	contains(l, "import tarfile as")
	some m in regex.find_all_string_submatch_n(`^\s*import\s+tarfile\s+as\s+(\w+)`, l, 1)
}

_mod_alt(lines) := concat("|", sort(_tar_mods(lines)))

# Names bound to a tarfile object anywhere in the file.
_tar_names(lines, alt) := {m[1] |
	some line in lines
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:(?:`, alt, `)\.)?(?:open|TarFile(?:\.open)?)\s*\([^\n]*?\)\s+as\s+(\w+)`]), line, -1)
	regex.match(concat("", [`\b(?:`, alt, `)\.(open|TarFile)|\bTarFile\.open`]), line)
} | {m[1] |
	# `tar = tarfile.open(...)` and `self.archive = tarfile.open(...)`
	some line in lines
	some m in regex.find_all_string_submatch_n(concat("", [`^\s*(?:(?:self|cls)\.)?(\w+)\s*=\s*(?:(?:`, alt, `)\.)?(?:open|TarFile(?:\.open)?)\s*\(`]), line, 1)
	regex.match(concat("", [`\b(?:`, alt, `)\.(open|TarFile)|\bTarFile\.open`]), line)
} | {m[1] |
	# A parameter annotated as one: `def install(bundle: tarfile.TarFile, ...)`.
	some line in lines
	contains(line, "TarFile")
	some m in regex.find_all_string_submatch_n(concat("", [`\b(\w+)\s*:\s*["']?(?:(?:`, alt, `)\.)?TarFile\b`]), line, -1)
}

# The call's argument text up to its closing parenthesis (at most six lines).
_call_text(lines, i) := lines[i] if regex.match(`\)\s*:?\s*(#.*)?$`, lines[i])

_call_text(lines, i) := t if {
	not regex.match(`\)\s*:?\s*(#.*)?$`, lines[i])
	end := min([count(lines) - 1, i + 6])
	end >= i + 1
	closes := [k | some k in numbers.range(i + 1, end); regex.match(`^\s*\)`, lines[k])]
	count(closes) > 0
	t := concat(" ", array.slice(lines, i, closes[0] + 1))
}

# The file installs its own extraction filter, on an archive or module-wide
# (archive.extraction_filter = my_filter, TarFile.extraction_filter =
# staticmethod(tarfile.data_filter)). Only fully_trusted_filter keeps the modes.
_module_filter(content) if {
	contains(content, "extraction_filter")
	regex.match(`(?m)^[^#\n]*\.extraction_filter\s*=`, content)
	not regex.match(`(?m)^[^#\n]*\.extraction_filter\s*=\s*(staticmethod\s*\(\s*)?(tarfile\.)?fully_trusted_filter\b`, content)
}

_unfiltered(text) if not regex.match(`\bfilter\s*=`, text)

# filter=None asks for the default, which keeps every mode bit before 3.14.
_unfiltered(text) if regex.match(`\bfilter\s*=\s*(["']fully_trusted["']|(tarfile\.)?fully_trusted_filter\b|None\b)`, text)

_tar_extract(line, names) if {
	some m in regex.find_all_string_submatch_n(`\b(\w+)\.extract(?:all)?\s*\(`, line, -1)
	m[1] in names
}

_tar_extract(line, _) if regex.match(`\btarfile\.open\s*\([^\n]*\)\.extract(all)?\s*\(`, line)

_py_finding(lines, i, line, names) if {
	_tar_extract(line, names)
	_unfiltered(_call_text(lines, i))
}

_py_finding(lines, i, line, _) if {
	regex.match(`\bshutil\.unpack_archive\s*\(`, line)
	text := _call_text(lines, i)
	_unfiltered(text)
	# A zip archive (format="zip", or a literal path ending in .zip) is
	# unpacked without its modes.
	not regex.match(`["']zip["']|\.zip["']`, text)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	_has_any(content, {"tarfile", "unpack_archive"})
	not helpers.is_test_path(path)
	not _module_filter(content)
	lines := split(content, "\n")
	names := _tar_names(lines, _mod_alt(lines))
	some i, line in lines
	_has_any(line, {".extract", "unpack_archive"})
	regex.match(`\.extract(all)?\s*\(|unpack_archive\s*\(`, line)
	not helpers.is_comment_line(line)
	_py_finding(lines, i, line, names)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Go: archive/tar and archive/zip ──────────────────────────────────────

# The entry's own mode, read from a tar header or a zip file header.
_hdr_mode := `\bFileMode\(\s*[\w.]+\.Mode\s*\)|\.FileInfo\(\)\.Mode\(\)`

# Loop variables ranging over a zip reader's entries.
_zip_vars(lines) := {m[1] |
	some line in lines
	some m in regex.find_all_string_submatch_n(`\bfor\s+_\s*,\s*(\w+)\s*:=\s*range\s+[\w.]+\.File\b`, line, 1)
}

_go_mode_source(zipvars) := concat("|", array.concat([_hdr_mode], [concat("", [`\b`, v, `\.Mode\(\)`]) | some v in zipvars]))

# Names holding an entry's FileInfo (`info := header.FileInfo()`), whose
# Mode() is the entry's mode, in the lines above i.
_go_info_vars(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 25]), i - 1)
	contains(lines[j], "FileInfo()")
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*:?=\s*[\w.\[\]]+\.FileInfo\(\)\s*$`, lines[j], 1)
	count(m) > 0
	v := m[0][1]
}

_go_preserves(lines, i, args, _) if {
	some v in _go_info_vars(lines, i)
	regex.match(concat("", [`\b`, v, `\.Mode\(\)`]), args)
}

_go_masked(args) if regex.match(`&\^?\s*\(?\s*0[oO]?[0-7]+`, args)

_go_preserves(lines, i, args, src) if regex.match(src, args)

# Names assigned the entry's mode, unmasked, in the lines above i.
_go_mode_vars(lines, i, src) := {v |
	i > 0
	some j in numbers.range(max([0, i - 20]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(src, lines[j])
	not _go_masked(lines[j])
	v := helpers.assigned_first(lines[j])
	# `mode &= 0o755` / `mode &^= 0o022` between the assignment and the call.
	not _go_remasked(lines, j, i, v)
}

_go_remasked(lines, j, i, v) if {
	some k in numbers.range(j + 1, i - 1)
	regex.match(concat("", [`(^|[^\w.])`, v, `\s*&\^?=\s*\(?\s*0[oO]?[0-7]+`]), lines[k])
}

_go_preserves(lines, i, args, src) if {
	some v in _go_mode_vars(lines, i, src)
	regex.match(concat("", [`,\s*`, v, `\s*\)`]), args)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_has_any(content, {"\"archive/tar\"", "\"archive/zip\""})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	src := _go_mode_source(_zip_vars(lines))
	some i, line in lines
	_has_any(line, {"os.", "Chmod"})
	regex.match(`\bos\.(OpenFile|Chmod|Mkdir|MkdirAll|WriteFile)\s*\(|\.Chmod\s*\(`, line)
	not helpers.is_comment_line(line)
	parts := regex.split(`\bos\.(OpenFile|Chmod|Mkdir|MkdirAll|WriteFile)\s*\(|\.Chmod\s*\(`, line)
	args := concat(" ", array.slice(parts, 1, count(parts)))
	not _go_masked(args)
	_go_preserves(lines, i, args, src)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Ownership restored from the entry: os.Chown(target, hdr.Uid, hdr.Gid).
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_has_any(content, {"\"archive/tar\"", "\"archive/zip\""})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"Chown", "Lchown"})
	regex.match(`\bos\.(Chown|Lchown)\s*\([^,]*,\s*[\w.]+\.Uid\b`, line)
	not helpers.is_comment_line(line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Rust: the tar crate ──────────────────────────────────────────────────

# Archive::set_preserve_permissions(true) keeps every mode bit of the entry
# (setuid included); set_preserve_ownerships(true) chowns to the entry's owner.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	contains(content, "set_preserve_")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "set_preserve_")
	not helpers.is_comment_line(line)
	regex.match(`\.set_preserve_(permissions|ownerships)\s*\(\s*true\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
