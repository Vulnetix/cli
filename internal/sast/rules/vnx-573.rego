# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_573

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-573",
	"name": "Remote URL read through an API that cannot set a timeout",
	"description": "A remote java.net.URL read through a convenience API that gives the caller no way to set a connect or read timeout, in Java or Kotlin: URL.openStream() (on new URL(...), URL(...), uri.toURL(), or a name declared as a URL in the file), Kotlin URL.readText()/readBytes(), commons-io IOUtils.toString/toByteArray(url) and two-argument FileUtils.copyURLToFile(url, file), Guava Resources.toString/toByteArray(url), and javax.imageio ImageIO.read(url). The URLConnection these open uses the JDK default of no timeout, so a slow or unresponsive server holds the calling thread indefinitely (CWE-573: the caller does not meet the network API's contract to bound the call). Not reported: classpath and file URLs (getResource(...), file.toURI().toURL(), \"file:\"/\"jar:\" literals), openConnection() with setConnectTimeout/setReadTimeout, the four-argument copyURLToFile with timeouts, a file that sets sun.net.client.defaultReadTimeout, File.readText() and readers, and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-573/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [573],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["improper-spec-api", "timeout", "network", "cwe-573"],
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "kt" if endswith(path, ".kt")

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `//.*$`, "")

_needles := {"openStream", "readText", "readBytes", "IOUtils.to", "copyURLToFile", "Resources.to", "ImageIO.read"}

# A URL that names a local resource, not a server.
_local_re := `getResource|getSystemResource|toURI\(\)\s*\.toURL|toUri\(\)\s*\.toURL|"(?:file|jar|jrt):`

# Names declared as a URL in the file, other than local resources.
_url_names(content, lines, "java") := {v |
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.])URL\s+(\w+)\s*[=;,)]`, content, -1)
	v := m[1]
	not _local_name(lines, v)
} | {v |
	some m in regex.find_all_string_submatch_n(`\bvar\s+(\w+)\s*=\s*new\s+URL\s*\(`, content, -1)
	v := m[1]
	not _local_name(lines, v)
}

_url_names(content, lines, "kt") := {v |
	some m in regex.find_all_string_submatch_n(`\b(\w+)\s*:\s*URL\b|\b(?:val|var)\s+(\w+)\s*=\s*URL\s*\(`, content, -1)
	some k in {1, 2}
	v := m[k]
	v != ""
	not _local_name(lines, v)
}

_local_name(lines, v) if {
	re := concat("", [`\b`, v, `\s*(?::\s*URL\??\s*)?=.*(?:`, _local_re, `)`])
	some l in lines
	contains(l, v)
	regex.match(re, l)
}

# An expression that is a fresh remote URL.
_fresh := `(?:\bnew\s+URL\s*\([^;]*\)|(?:^|[^\w.])URL\s*\([^;]*\)|\b\w+\.toURL\(\))`

_hit(c, _, lang, raw) if {
	regex.match(concat("", [_fresh, `\s*\.(?:openStream\(\)`, _kt_reads(lang), `)`]), c)
	not regex.match(_local_re, raw)
}

_hit(c, names, lang, _) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])(?:this\.)?(\w+)\s*\.(?:openStream\(\)`, _kt_reads(lang), `)`]), c, -1)
	m[1] in names
}

_hit(c, names, _, _) if {
	some m in regex.find_all_string_submatch_n(`\b(?:(?:IOUtils|Resources)\.to(?:String|ByteArray)|ImageIO\.read)\(\s*((?:this\.)?\w+|(?:new\s+)?URL\s*\()`, c, -1)
	_remote_arg(m[1], names)
}

_hit(c, names, _, _) if {
	some m in regex.find_all_string_submatch_n(`\bFileUtils\.copyURLToFile\(\s*((?:this\.)?\w+|new\s+URL\s*\([^()]*\))\s*,\s*[^,()]+(?:\([^()]*\))?\s*\)`, c, -1)
	_remote_arg(m[1], names)
}

_remote_arg(a, _) if startswith(a, "new")

_remote_arg("URL", _)

_remote_arg(a, names) if trim_prefix(a, "this.") in names

_kt_reads("kt") := `|readText\(|readBytes\(`

_kt_reads("java") := ""

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	some n in _needles
	contains(content, n)
	not contains(content, "sun.net.client.defaultReadTimeout")
	lines := split(content, "\n")
	names := _url_names(content, lines, lang)
	some i, line in lines
	_has_needle(line)
	not helpers.is_comment_line(line)
	_hit(_code(line), names, lang, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Remote URL read with no connect or read timeout: an unresponsive server blocks this thread indefinitely. Open a URLConnection (or HttpClient) and set connect and read timeouts",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_has_needle(line) if {
	some n in _needles
	contains(line, n)
}
