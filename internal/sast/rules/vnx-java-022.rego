package vulnetix.rules.vnx_java_022

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-022",
	"name": "Java insecure temporary file creation",
	"description": "A temporary file is created where other local users can read it or predict it. Reported: java.io.File.createTempFile() in the shared temp directory (two arguments, or a third argument of null or java.io.tmpdir), which creates the file with umask permissions (typically world-readable, CVE-2020-15250) and whose delete()/mkdir() idiom is racy, unless the next lines restrict it with setPosixFilePermissions/setReadable/setWritable; and fixed or user-derived names in a shared temp directory, which an attacker can pre-create or symlink: new File/FileOutputStream/FileWriter/RandomAccessFile/PrintWriter, Paths.get, Path.of and Files.write/createFile/newOutputStream on a \"/tmp/...\" or \"/var/tmp/...\" literal, and new File/Paths.get/Path.of joining System.getProperty(\"java.io.tmpdir\") (inline or through a variable) with a literal name. Not reported: Files.createTempFile/createTempDirectory (owner-only on POSIX), File.createTempFile in a caller-supplied directory, names built from UUID or SecureRandom, relative paths such as \"tmp/x\", test sources, and the pattern in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-022/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [377],
	"capec": ["CAPEC-29"],
	"attack_technique": ["T1036"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["file", "tempfile", "race-condition", "java"],
}

_strip_strings(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 3])
	ends := [k | some k in numbers.range(i, end); contains(lines[k], ";")]
	last := _first_or(ends, end)
	s := concat(" ", [regex.replace(lines[k], `//[^"]*$`, "") | some k in numbers.range(i, last)])
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_random := `UUID|SecureRandom|randomUUID|nextLong|nextInt|createTemp`

_file_api := `(?:new\s+(?:java\.io\.)?(?:File|FileOutputStream|FileWriter|RandomAccessFile|PrintWriter)|Paths\s*\.\s*get|Path\s*\.\s*of|Files\s*\.\s*(?:write|writeString|newOutputStream|newBufferedWriter|createFile))\s*\(\s*`

# ── File.createTempFile in the shared temp directory ─────────────────────

_k_tempfile(lines, i, line, code) if {
	regex.match(`\bFile\s*\.\s*createTempFile\s*\(`, code)
	stmt := _stmt(lines, i)
	sc := _strip_strings(stmt)
	_shared_dir(stmt, sc)
	not _restricted_after(lines, i)
}

_shared_dir(_, sc) if regex.match(`createTempFile\s*\(\s*[^,;]*,\s*[^,;]*?\)\s*[;.)]`, sc)

_shared_dir(stmt, sc) if {
	regex.match(`createTempFile\s*\(\s*[^,;]*,\s*[^,;]*,\s*null\s*\)`, sc)
}

_shared_dir(stmt, _) if regex.match(`createTempFile\s*\([^;]*java\.io\.tmpdir`, stmt)

_restricted_after(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 6]))
	regex.match(`setPosixFilePermissions|setReadable\s*\(|setWritable\s*\(|PosixFilePermissions`, lines[k])
}

# ── Predictable names in /tmp ────────────────────────────────────────────

_k_tmp_literal(lines, i, line, code) if {
	regex.match(concat("", [_file_api, `""`]), code)
	stmt := _stmt(lines, i)
	regex.match(concat("", [_file_api, `"/(?:var/)?tmp(?:/[^"]+"|/?"\s*[+,])`]), stmt)
	not regex.match(_random, stmt)
}

_k_tmpdir_fixed(lines, i, line, code) if {
	contains(line, "java.io.tmpdir")
	stmt := _stmt(lines, i)
	regex.match(concat("", [_file_api, `System\s*\.\s*getProperty\s*\(\s*"java\.io\.tmpdir"\s*\)\s*[,+]\s*(?:File\s*\.\s*separator\s*\+\s*)?"[^"]+"`]), stmt)
	not regex.match(_random, stmt)
}

_k_tmpdir_var(lines, i, line, code) if {
	regex.match(_file_api, code)
	stmt := _stmt(lines, i)
	some j in numbers.range(max([0, i - 15]), i - 1)
	contains(lines[j], "java.io.tmpdir")
	not helpers.is_comment_line(lines[j])
	v := helpers.assigned_first(lines[j])
	regex.match(concat("", [_file_api, v, `\s*[,+]\s*(?:File\s*\.\s*separator\s*\+\s*|"/"\s*\+\s*)?"[^"]+"`]), stmt)
	not regex.match(_random, stmt)
}

_kind(lines, i, line, code) := "tempfile" if {
	_k_tempfile(lines, i, line, code)
} else := "tmp-literal" if {
	_k_tmp_literal(lines, i, line, code)
} else := "tmpdir-fixed" if {
	_k_tmpdir_fixed(lines, i, line, code)
} else := "tmpdir-var" if {
	_k_tmpdir_var(lines, i, line, code)
}

_msg := {
	"tempfile": "File.createTempFile() creates the file in the shared temp directory with umask permissions (often world-readable); use Files.createTempFile(), which is owner-only on POSIX, or restrict the permissions before writing",
	"tmp-literal": "Predictable file name in a shared temp directory; another local user can pre-create or symlink it. Use Files.createTempFile() or a private directory",
	"tmpdir-fixed": "Fixed file name under java.io.tmpdir; another local user can pre-create or symlink it. Use Files.createTempFile() or a private directory",
	"tmpdir-var": "Fixed file name under java.io.tmpdir; another local user can pre-create or symlink it. Use Files.createTempFile() or a private directory",
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`createTempFile|"/(var/)?tmp|java\.io\.tmpdir`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`createTempFile|File|Path|java\.io\.tmpdir`, line)
	not helpers.is_comment_line(line)
	code := _strip_strings(line)
	kind := _kind(lines, i, line, code)
	finding := {
		"rule_id": metadata.id,
		"message": _msg[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
