package vulnetix.rules.vnx_java_014

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-014",
	"name": "Java zip/tar slip via archive entry name",
	"description": "The name of an archive entry (java.util.zip ZipEntry, java.util.jar JarEntry, Apache Commons Compress TarArchiveEntry/ZipArchiveEntry/ArchiveEntry and similar) is used to build an output path without a containment check: new File/FileOutputStream/FileWriter/RandomAccessFile, Paths.get, Path.of, Path.resolve/resolveSibling or Files.newOutputStream/copy/write/createFile/createDirectories, whose arguments contain entry.getName() directly, getNextEntry().getName(), or a local assigned from it up to three assignments earlier within 15 lines. An entry named ../../etc/cron.d/x then writes outside the extraction directory. The entry variable is recognised from its declared type, from `(entry = zis.getNextEntry()) != null`, and from `var e = entries.nextElement()` in a file that uses an archive API. Not reported: extraction that checks containment within 15 lines before or 12 after (getCanonicalPath/getCanonicalFile/toRealPath/normalize() together with startsWith, or the name tested for \"..\"), names reduced to a bare file name (FilenameUtils.getName, Paths.get(name).getFileName()), the same path reported again when opened after the line that built it, listing or logging entry names, File.getName() and Class.getName(), and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-014/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "zip-slip", "java"],
}

_archive_re := `\b(?:(?:Zip|Jar|Tar|TarArchive|ZipArchive|Archive|SevenZArchive|ArArchive|CpioArchive|ArjArchive|DumpArchive)Entry|ZipFile|JarFile)\b`

# Entry variables of the file.
_entry_decl_re := `\b(?:Zip|Jar|Tar|TarArchive|ZipArchive|Archive|SevenZArchive|ArArchive|CpioArchive|ArjArchive|DumpArchive)Entry(?:<[^>]*>)?\s+(\w+)\s*[=;:,)]`

_entry_assign_re := `(?:\bvar\s+|\(\s*)(\w+)\s*=\s*\w+\s*\.\s*(?:getNext\w*Entry|nextElement)\s*\(`

_entry_vars(lines) := {m[1] |
	some l in lines
	contains(l, "Entry")
	some m in regex.find_all_string_submatch_n(_entry_decl_re, l, -1)
} | {m[1] |
	some l in lines
	regex.match(`getNext\w*Entry|nextElement`, l)
	some m in regex.find_all_string_submatch_n(_entry_assign_re, l, -1)
} | _lambda_entry_vars(lines)

_sink_re := `\bnew\s+(?:java\.io\.)?(?:File|FileOutputStream|FileWriter|RandomAccessFile)\s*\(|\b(?:Paths\.get|Path\.of)\s*\(|\.(?:resolve|resolveSibling)\s*\(|\bFiles\.(?:newOutputStream|newBufferedWriter|copy|write|writeString|createFile|createDirectories|createDirectory)\s*\(`

_sanitizer_re := `FilenameUtils\.getName\s*\(|\.getFileName\s*\(\s*\)|\bnew\s+File\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*\.\s*getName\s*\(\s*\)`

_blank(s) := regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`)

_name_re(vars) := concat("", [`\b(?:`, concat("|", vars), `)\s*\.\s*getName\s*\(\s*\)|\.getNext\w*Entry\s*\(\s*\)\s*\.\s*getName\s*\(`])

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:[\w.]+(?:<[^=;]*>)?(?:\[\])*\s+)?(\w+)\s*=(?:[^=]|$)`, line, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"if", "return", "else", "case", "this"}
}

# Locals holding the entry name: assigned from getName() or from such a local.
_names(lines, i, nre) := t if {
	assigns := [[v, _blank(lines[j])] |
		some j in numbers.range(max([0, i - 15]), i - 1)
		not helpers.is_comment_line(lines[j])
		v := _assigned(lines[j])
	]
	t0 := {a[0] | some a in assigns; regex.match(nre, a[1]); not regex.match(_sanitizer_re, a[1])}
	t := _hop(assigns, _hop(assigns, _hop(assigns, t0)))
}

_hop(_, t) := t if count(t) == 0

_hop(assigns, t) := t | {a[0] |
	some a in assigns
	regex.match(re, a[1])
	not regex.match(_sanitizer_re, a[1])
} if {
	count(t) > 0
	re := concat("", [`\b(?:`, concat("|", t), `)\b`])
}

_stmt(lines, i) := concat(" ", [_blank(lines[k]) | some k in numbers.range(i, e)]) if {
	last := min([count(lines) - 1, i + 3])
	ends := [k | some k in numbers.range(i, last); regex.match(`[;{]\s*$`, lines[k])]
	e := min(array.concat(ends, [last]))
}

_balanced(tail) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, tail, 1)
	count(m) > 0
} else := tail

_sink_args(stmt) := [_balanced(m[1]) | some m in regex.find_all_string_submatch_n(concat("", ["(?:", _sink_re, ")(.*)"]), stmt, -1)]

_uses_name(args, nre, _) if regex.match(nre, args)

_uses_name(args, _, t) if {
	count(t) > 0
	regex.match(concat("", [`\b(?:`, concat("|", t), `)\b`]), args)
}

# Containment is checked near the sink.
_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 15, 12)
	regex.match(`getCanonicalPath|getCanonicalFile|toRealPath|\.normalize\s*\(\s*\)`, w)
	contains(w, "startsWith(")
}

_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 15, 12)
	regex.match(`(?:getName\s*\(\s*\)|\w)\s*\.\s*(?:contains|indexOf)\s*\(\s*"\.\."`, w)
}

# The path was produced by an earlier sink line of the same extraction, which
# is already reported: `File out = new File(dir, e.getName()); new FileOutputStream(out)`.
_derived_from_sink(lines, i, args, nre) if {
	not regex.match(nre, args)
	ids := {m[0] | some m in regex.find_all_string_submatch_n(`\b[A-Za-z_]\w*\b`, args, -1)}
	some j in numbers.range(max([0, i - 15]), i - 1)
	v := _assigned(lines[j])
	v in ids
	regex.match(_sink_re, _blank(lines[j]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "getName")
	regex.match(_archive_re, content)
	lines := split(content, "\n")
	vars := _entry_vars(lines)
	count(vars) > 0
	nre := _name_re(vars)
	some i, line in lines
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _blank(line))
	t := _names(lines, i, nre)
	stmt := _stmt(lines, i)
	some args in _sink_args(stmt)
	not regex.match(_sanitizer_re, args)
	_uses_name(args, nre, t)
	not _derived_from_sink(lines, i, args, nre)
	not _guarded(lines, i)
	not regex.match(_bare_name_after_re, stmt)
	finding := {
		"rule_id": metadata.id,
		"message": "Archive entry name used in an output path without a containment check (zip slip); resolve and normalise the path, then verify it still starts with the extraction directory before writing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The path object is only built to take its last component:
# new File(e.getName()).getName(), Paths.get(e.getName()).getFileName().
_bare_name_after_re := `(?:\b(?:Paths\.get|Path\.of)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*\.\s*getFileName|\bnew\s+File\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*\.\s*getName)\s*\(\s*\)`

# zipFile.stream().forEach(e -> ...): the lambda parameter is an entry when
# the stream comes from a ZipFile/JarFile local or field of the file.
_zipfile_vars(lines) := {m[1] |
	some l in lines
	regex.match(`\b(?:ZipFile|JarFile)\b`, l)
	some m in regex.find_all_string_submatch_n(`\b(?:ZipFile|JarFile)\s+(\w+)\s*[=;)]`, l, -1)
}

_lambda_entry_vars(lines) := set() if count(_zipfile_vars(lines)) == 0

_lambda_entry_vars(lines) := {m[1] |
	zf := _zipfile_vars(lines)
	re := concat("", [`\b(?:`, concat("|", zf), `)\s*\.\s*stream\s*\(\s*\)[^;]*\.\s*forEach\s*\(\s*\(?\s*(\w+)\s*\)?\s*->`])
	some l in lines
	contains(l, "forEach")
	some m in regex.find_all_string_submatch_n(re, l, 1)
} if count(_zipfile_vars(lines)) > 0
