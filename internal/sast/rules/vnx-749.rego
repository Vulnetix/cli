# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_749

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-749",
	"name": "Dangerous capability exposed to WebView JavaScript",
	"description": "An Android @JavascriptInterface method, which any script running in the WebView can call through the bridge registered with addJavascriptInterface, performs a dangerous operation on the caller's behalf, so content the WebView loads (or script injected into it) inherits that capability. Reported in Java and Kotlin: inside a method annotated @JavascriptInterface (android.webkit.JavascriptInterface), a call that runs a command (Runtime.getRuntime().exec, ProcessBuilder), writes or deletes files (FileOutputStream, FileWriter, openFileOutput, Files.write/delete/move/copy, File.delete()), loads or invokes code by name (Class.forName, getMethod/getDeclaredMethod, Method.invoke, DexClassLoader/PathClassLoader, System.load/loadLibrary), runs SQL (execSQL, rawQuery), sends SMS (SmsManager.sendTextMessage/sendMultipartTextMessage), launches components (startActivity, startService, sendBroadcast) or reads device identifiers and location (getDeviceId, getImei, getLine1Number, getSubscriberId, getLastKnownLocation). The finding is on the dangerous call. Not reported: bridge methods that only return values, log, show UI or post to a handler; the same calls in methods without the annotation; addJavascriptInterface itself (VNX-ANDROID-002 reports a bridge registered on a WebView that loads untrusted content); test code, comments and strings. Bridges exposed through other frameworks (Cordova plugins, React Native modules) are not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-749/",
	"languages": ["java", "kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [749],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["dangerous-method", "android", "webview", "javascript-interface", "cwe-749"],
}

_lang_file(path) if endswith(path, ".java")

_lang_file(path) if endswith(path, ".kt")

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

_sink_re := `\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcessBuilder\s*\(|\bFileOutputStream\s*\(|\bFileWriter\s*\(|\bopenFileOutput\s*\(|\bFiles\.(write|writeString|delete|deleteIfExists|move|copy|newOutputStream|newBufferedWriter)\s*\(|\bRandomAccessFile\s*\(|\.delete\(\)|\.(writeText|writeBytes|appendText|appendBytes|outputStream|bufferedWriter|printWriter|deleteRecursively|renameTo)\s*\(|\bClass\.forName\s*\(|\.getDeclaredMethod\s*\(|\.getMethod\s*\(|\.invoke\s*\(|\b(DexClassLoader|PathClassLoader|InMemoryDexClassLoader)\s*\(|\bSystem\.(load|loadLibrary)\s*\(|\.execSQL\s*\(|\.rawQuery\s*\(|\.(sendTextMessage|sendMultipartTextMessage|sendDataMessage)\s*\(|\b(startActivity|startService|sendBroadcast)\s*\(|\.(getDeviceId|getImei|getLine1Number|getSubscriberId|getSimSerialNumber|getLastKnownLocation)\s*\(`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The method declaration the annotation at a applies to: the annotation line
# itself when the declaration follows on it, otherwise the next code line
# that is not another annotation.
_decl(lines, a) := a if regex.match(`@(android\.webkit\.)?JavascriptInterface\s+(public|private|protected|fun|final|open|override|internal|[A-Za-z_][\w<>\[\]]*\s+\w+\s*\()`, lines[a])

_decl(lines, a) := d if {
	not regex.match(`@(android\.webkit\.)?JavascriptInterface\s+(public|private|protected|fun|final|open|override|internal|[A-Za-z_][\w<>\[\]]*\s+\w+\s*\()`, lines[a])
	end := min([count(lines) - 1, a + 4])
	a + 1 <= end
	cands := [k |
		some k in numbers.range(a + 1, end)
		t := trim_space(lines[k])
		t != ""
		not helpers.is_comment_line(lines[k])
		not startswith(t, "@")
	]
	count(cands) > 0
	d := cands[0]
}

# The method body: from the declaration to the closing brace at its indent
# (or the next annotated member), bounded to 60 lines.
_body_end(lines, d) := e if {
	ind := _indent(lines[d])
	limit := min([count(lines) - 1, d + 60])
	d + 1 <= limit
	ends := [k |
		some k in numbers.range(d + 1, limit)
		_indent(lines[k]) <= ind
		trim_space(lines[k]) != ""
	]
	e := min(array.concat([limit], ends))
}

findings contains finding if {
	some path, content in input.file_contents
	_lang_file(path)
	contains(content, "JavascriptInterface")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, aline in lines
	contains(aline, "JavascriptInterface")
	regex.match(`^\s*@(android\.webkit\.)?JavascriptInterface\b`, aline)
	d := _decl(lines, a)
	e := _body_end(lines, d)
	some k in numbers.range(d, e)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_sink_re, _code(l))
	finding := {
		"rule_id": metadata.id,
		"message": "This @JavascriptInterface method performs a dangerous operation (command, file write/delete, reflection, SQL, SMS, component launch or device identifiers) for any script in the WebView. Expose only narrow, validated operations to JavaScript and never load untrusted content into a WebView with a bridge",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": l,
	}
}
