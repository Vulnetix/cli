package vulnetix.rules.vnx_java_023

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-023",
	"name": "Java unrestricted file upload — no content-type or extension validation",
	"description": "An uploaded file is written to disk under the name the client sent, with no check of its extension or content type, so an attacker can store a .jsp, .war or other executable or browser-active file where the server or its users will run it. Reported: a write sink (MultipartFile.transferTo, Files.copy/write/move, new FileOutputStream, Part.write, FileItem.write, commons-io FileUtils.copyInputStreamToFile/copyToFile/writeByteArrayToFile) whose destination uses MultipartFile.getOriginalFilename(), Part.getSubmittedFileName() or FileItem.getName(), inline, through a variable assigned from it, or through one more assignment (Path target = dir.resolve(name)), within 25 lines. Not reported: when the 30 lines above the sink check the name or type (endsWith, FilenameUtils.getExtension, an ALLOWED/allowlist set, getContentType, probeContentType, Tika, matches(), a call to a validate* helper; a @Validated annotation or an import is not a check); files stored under a generated name (UUID) while the original name is only logged or saved as metadata; and the pattern in comments or string literals. Path traversal through the same name is a separate weakness (CWE-22).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-023/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [434],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["file-upload", "cwe-434", "java"],
}

_src := `\.\s*(getOriginalFilename|getSubmittedFileName)\s*\(\s*\)|(?i:\b\w*item)\s*\.\s*getName\s*\(\s*\)`

_sink := `\.\s*transferTo\s*\(|\bFiles\s*\.\s*(copy|write|move)\s*\(|new\s+FileOutputStream\s*\(|(?i:\b\w*(part|item))\s*\.\s*write\s*\(|FileUtils\s*\.\s*(copyInputStreamToFile|copyToFile|writeByteArrayToFile)\s*\(`

_validation := `endsWith\s*\(|getExtension|(?i:allow(ed)?_?(list|types|extensions|ext|mime))|ALLOWED|(?i:whitelist)|getContentType\s*\(|probeContentType|\bTika\b|\.\s*matches\s*\(|\.\s*contains\s*\(\s*(?i:(?:file_?|upload_?)?(?:ext|extension|suffix|content_?type|mime_?type|type))(?:\s*\.\s*to(?:Lower|Upper)Case\s*\([^)]*\))?\s*\)|(?i:validat\w*\s*\(|isAllowed|checkExtension|checkType|mime_?type)`

_strip_strings(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 3])
	ends := [k | some k in numbers.range(i, end); contains(lines[k], ";")]
	last := _first_or(ends, end)
	s := _strip_strings(concat(" ", [regex.replace(lines[k], `//[^"]*$`, "") | some k in numbers.range(i, last)]))
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_word(v) := concat("", [`\b`, v, `\b`])

_tainted(lines, i) := t1 | t2 if {
	t1 := helpers.tainted_names(lines, i, 25, _src)
	t2 := {w |
		some j in numbers.range(max([0, i - 25]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		some v in t1
		regex.match(_word(v), _strip_strings(l))
		w := helpers.assigned_first(l)
		w != v
		not regex.match(`UUID|randomUUID|SecureRandom`, l)
	}
}

# Files.write(target, bytes...) with a plain variable as the target: only the
# target decides where the upload lands; the name in the content is data.
_dest(stmt) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`\bFiles\s*\.\s*write\s*\(\s*((?:this\.)?[A-Za-z_]\w*)\s*,`, stmt, 1)
	count(m) > 0
} else := stmt

_uses_name(_, _, stmt) if regex.match(_src, stmt)

_uses_name(lines, i, stmt) if {
	some v in _tainted(lines, i)
	regex.match(_word(v), stmt)
}

_validated(lines, i) if {
	some j in numbers.range(max([0, i - 30]), i)
	not helpers.is_comment_line(lines[j])
	not regex.match(`^\s*(@|import\s)`, lines[j])
	regex.match(_validation, _strip_strings(lines[j]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`getOriginalFilename|getSubmittedFileName|FileItem`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`transferTo|Files|FileOutputStream|write|FileUtils`, line)
	not helpers.is_comment_line(line)
	regex.match(_sink, _strip_strings(line))
	stmt := _stmt(lines, i)
	_uses_name(lines, i, _dest(stmt))
	not _validated(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Uploaded file is stored under the client-supplied name without an extension or content-type check; validate against an allowlist (or store under a generated name) so executable files such as .jsp cannot be uploaded",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
