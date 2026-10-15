# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_66

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-66",
	"name": "Improper Handling of File Names that Identify Virtual Resources",
	"description": "An uploaded file is stored under the name the client sent, so a name such as CON, NUL, AUX, COM1 or LPT1 (with or without an extension) opens a Windows device instead of a file, and the upload hangs the worker, discards data or writes to a port. Reported: the client file name (Python werkzeug/FastAPI .filename of request.files or UploadFile, Django request.FILES[...].name; Java MultipartFile.getOriginalFilename(), Part.getSubmittedFileName(); C# IFormFile/HttpPostedFile .FileName; Go multipart FileHeader .Filename) placed in a file-system path or write call (os.path.join, open, .save, Path; new File, Paths.get, Path.of, resolve, FileOutputStream, transferTo, Files.copy/write/move, servlet Part.write; Path.Combine, File.Create/OpenWrite/WriteAll*/Move/Copy, FileStream, SaveAs, MapPath; filepath.Join, path.Join, os.Create/OpenFile/WriteFile, SaveUploadedFile/SaveFile), on the same line or through a variable assigned from it in the 15 lines above. Stripping directories (basename, Path.GetFileName, FilenameUtils.getName, filepath.Base) does not remove a device name and is still reported. Not reported: a name passed through secure_filename or a sanitize/sanitise function, a generated name on the write line (uuid, Guid, random, GetRandomFileName, hash, timestamp), a project that checks names against the reserved device list, the name only logged or stored, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-66/",
	"languages": ["csharp", "go", "java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [66],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["filename", "virtual-resource", "windows", "upload", "cwe-66"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "cs" if endswith(path, ".cs")

_lang(path) := "go" if endswith(path, ".go")

# The file handles uploads at all.
_upload_needles := {
	"py": {"request.files", "request.FILES", "UploadFile", "FileStorage"},
	"java": {"getOriginalFilename", "getSubmittedFileName"},
	"cs": {"IFormFile", "HttpPostedFile", "PostedFile", "Request.Files", "Request.Form.Files", "FileUpload", ".SaveAs("},
	"go": {"FormFile(", "multipart."},
}

_name_needle := {"py": ".filename", "java": "Filename()", "cs": ".FileName", "go": ".Filename"}

_name_re := {
	"py": `\.filename\b|\brequest\.FILES\s*\[[^\]]+\]\.name\b`,
	"java": `\.(getOriginalFilename|getSubmittedFileName)\s*\(\s*\)`,
	"cs": `\.FileName\b`,
	"go": `\.Filename\b`,
}

_sink_re := {
	"py": `\bos\.path\.join\s*\(|(^|[^\w.])open\s*\(|\.save\s*\(|\bPath\s*\(|\bshutil\.(copy|move)\w*\s*\(`,
	"java": `\bnew\s+File\s*\(|\bPaths\.get\s*\(|\bPath\.of\s*\(|\.resolve\s*\(|\bnew\s+FileOutputStream\s*\(|\.transferTo\s*\(|\bFiles\.(copy|write|move)\s*\(|\b\w*[Pp]art\w*\s*\.\s*write\s*\(`,
	"cs": `\bPath\.Combine\s*\(|\bFile\.(Create|OpenWrite|WriteAll\w*|Move|Copy)\s*\(|\bnew\s+FileStream\s*\(|\.SaveAs\s*\(|\bMapPath\s*\(`,
	"go": `\b(filepath|path)\.Join\s*\(|\bos\.(Create|OpenFile|WriteFile)\s*\(|\bioutil\.WriteFile\s*\(|\.(SaveUploadedFile|SaveFile)\s*\(`,
}

# A generated or sanitised name replaces the client's.
_replaced := `(?i)secure_filename|saniti[sz]|uuid|guid|random|hash|digest|nanoid|ulid|time\.Now|currentTimeMillis|nanoTime|DateTime|Instant\.now|\bdatetime\b|\btime\.time\(`

# The project rejects the reserved device names itself.
_checks_reserved(content) if regex.match(`(?i)["'\s,(\[{]CON["'\s,)\]}|].*["'\s,(\[{](PRN|AUX|NUL)["'\s,)\]}|]`, content)

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	contains(content, _name_needle[lang])
	_has_any(content, _upload_needles[lang])
	not _checks_reserved(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_sink_re[lang], line)
	not regex.match(_replaced, line)
	not regex.match(_logging, line)
	_client_name(lang, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "The uploaded file is stored under the name the client sent. On Windows a name like CON, NUL, AUX, COM1 or LPT1 (any extension) is a device, not a file, so the write hangs, is discarded or reaches a port; basename/GetFileName does not remove it. Store the upload under a generated name (UUID) and keep the original only as data, or reject reserved device names",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_client_name(lang, _, _, line) if regex.match(_name_re[lang], line)

_client_name(lang, lines, i, line) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	regex.match(_name_re[lang], prev)
	# a path built on that line is reported there, not again where it is used
	not regex.match(_sink_re[lang], prev)
	not helpers.is_comment_line(prev)
	not regex.match(_replaced, prev)
	v := helpers.assigned_first(prev)
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

# A path printed in a log line is not written.
_logging := `(?i)\b(log|logger|logging|console|slf4j)\s*\.\s*(debug|info|warn\w*|error|trace|log|print\w*)\s*\(|^\s*print\s*\(`
