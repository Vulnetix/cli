package vulnetix.rules.vnx_android_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-ANDROID-002",
	"name": "Android WebView runs JavaScript from untrusted content",
	"description": "A WebView with JavaScript enabled (setJavaScriptEnabled(true) or Kotlin javaScriptEnabled = true in the same file) is made to run content an attacker controls. Reported, in Java and Kotlin: a loadUrl/loadData/loadDataWithBaseURL/postUrl/evaluateJavascript call whose URL, HTML or script comes from the launching Intent or a deep link (getIntent(), intent.getStringExtra/getData/data/extras, getQueryParameter, Fragment getArguments/requireArguments), from external storage (getExternalStorageDirectory/getExternalFilesDir, world-writable on older devices), or is a cleartext http:// URL that the network can rewrite, directly in the call or through a variable assigned from such a source up to 15 lines above; addJavascriptInterface in a file that has such a load, since the bridge is then callable by that content; and setAllowUniversalAccessFromFileURLs(true) / setAllowFileAccessFromFileURLs(true) (allowUniversalAccessFromFileURLs / allowFileAccessFromFileURLs = true), which let a file:// page read any origin or any local file. Not reported: JavaScript enabled on its own, loads of https:// or file:///android_asset/ literals and BuildConfig/constant URLs, an intent URL checked first (startsWith, host/scheme comparison, an allow-list, a validator) between the read and the load, loads with JavaScript disabled, Custom Tabs and non-WebView loaders in files that enable no JavaScript, http://localhost, the default setAllowFileAccess, comments and strings. Flows through other methods or files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-002/",
	"languages": ["java", "kotlin"],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["android", "webview", "xss", "mobile-security"],
}

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".kt")

# String literals blanked, so an API named inside a string is not a call.
_code(s) := regex.replace(s, `"(\\.|[^"\\])*"`, `""`)

_js_enabled(lines) if {
	some line in lines
	contains(line, "avaScriptEnabled")
	not helpers.is_comment_line(line)
	regex.match(`setJavaScriptEnabled\s*\(\s*true\s*\)|\bjavaScriptEnabled\s*=\s*true\b`, _code(line))
}

# ── Untrusted content ────────────────────────────────────────────────────

_source_re := `getIntent\s*\(\s*\)|\bintent\s*[?!]*\s*\.\s*(getStringExtra|getCharSequenceExtra|getData|data|getDataString|dataString|getExtras|extras|getBundleExtra)\b|\.getStringExtra\s*\(|\.getQueryParameter\s*\(|\b(getArguments\s*\(\s*\)|requireArguments\s*\(\s*\)|arguments)\s*[?!]*\s*\.\s*getString\s*\(|getExternalStorageDirectory\s*\(|getExternalStoragePublicDirectory\s*\(|getExternalFilesDir\s*\(|getExternalCacheDir\s*\(|\bexternalCacheDir\b`

_untrusted(text) if regex.match(_source_re, _code(text))

_untrusted(text) if {
	regex.match(`"http://[^"]`, text)
	not regex.match(`"http://(localhost|127\.0\.0\.1|10\.0\.2\.2|\[::1\])([:/"]|$)`, text)
}

_sink_word(s) if contains(s, "load")

_sink_word(s) if contains(s, "evaluateJavascript")

_sink_re :=`(^|[^\w])(loadUrl|loadData|loadDataWithBaseURL|postUrl|evaluateJavascript)\s*\(`

# A declaration of a method with that name is not a call.
_declaration(line) if regex.match(`\b(fun|void|public|private|protected|override)\b[^=]*\b(loadUrl|loadData|loadDataWithBaseURL|postUrl|evaluateJavascript)\s*\(`, line)

# The argument text of the load call on line i (it may span lines).
_sink_args(lines, i) := ms[0][3] if {
	text := concat(" ", array.slice(lines, i, min([count(lines), i + 9])))
	ms := regex.find_all_string_submatch_n(`(^|[^\w])(loadUrl|loadData|loadDataWithBaseURL|postUrl|evaluateJavascript)\s*\(((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*)\)`, text, 1)
	count(ms) > 0
}

_assigned(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:private|public|protected|internal|final|static|override|lateinit)\s+)*(?:val\s+|var\s+)?(?:[\w.<>\[\]?]+\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w.<>?\[\], ]+)?\s*=[^=]`, line, 1)
	count(m) > 0
}

_guard_re := `(?i)(startsWith\s*\(|getHost\s*\(|getScheme\s*\(|\.host\b|\.scheme\b|allow|whitelist|trusted|isValid|validat|sanitiz|matches\s*\(|equals\s*\(|isHttpsUrl|isNetworkUrl)`

_guarded(lines, j, i, v) if {
	some k in numbers.range(j + 1, i)
	l := lines[k]
	contains(l, v)
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b`, v, `\b`]), l)
	regex.match(_guard_re, l)
}

_is_sink(lines, i) if {
	line := lines[i]
	_sink_word(line)
	not helpers.is_comment_line(line)
	not _declaration(line)
	regex.match(_sink_re, _code(line))
}

# Directly from a source.
_untrusted_load(lines, i) if {
	_is_sink(lines, i)
	_untrusted(_sink_args(lines, i))
}

# Through a variable assigned from a source a few lines above.
_untrusted_load(lines, i) if {
	_is_sink(lines, i)
	args := _sink_args(lines, i)
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	_untrusted(prev)
	v := _assigned(prev)
	regex.match(concat("", [`\b`, v, `\b`]), args)
	not _guarded(lines, j, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "avaScriptEnabled")
	_sink_word(content)
	lines := split(content, "\n")
	_js_enabled(lines)
	some i, line in lines
	_sink_word(line)
	_untrusted_load(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "A JavaScript-enabled WebView loads content an attacker controls (an Intent or deep-link value, a file on external storage, or a cleartext http:// page); its script then runs with the WebView's access to cookies, files and any JavaScript bridge. Allow-list the scheme and host before loading, serve the page over HTTPS, and disable JavaScript where it is not needed",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "addJavascriptInterface")
	contains(content, "avaScriptEnabled")
	lines := split(content, "\n")
	_js_enabled(lines)
	some i, line in lines
	contains(line, "addJavascriptInterface")
	not helpers.is_comment_line(line)
	regex.match(`\baddJavascriptInterface\s*\(`, _code(line))
	some k, l in lines
	_sink_word(l)
	_untrusted_load(lines, k)
	finding := {
		"rule_id": metadata.id,
		"message": "addJavascriptInterface exposes native methods to every page this WebView loads, and this file loads attacker-controlled content into it, so that content can call the bridge. Load only allow-listed origins, or replace the bridge with WebViewCompat.addWebMessageListener scoped to trusted origins",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "AccessFromFileURLs")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "AccessFromFileURLs")
	not helpers.is_comment_line(line)
	regex.match(`setAllow(Universal|File)AccessFromFileURLs\s*\(\s*true\s*\)|\ballow(Universal|File)AccessFromFileURLs\s*=\s*true\b`, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Allowing file:// pages universal or file access lets any script in a local page read other origins or every file the app can read, and send them anywhere. Leave setAllowUniversalAccessFromFileURLs and setAllowFileAccessFromFileURLs false; serve local content with WebViewAssetLoader over https://appassets.androidplatform.net instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
