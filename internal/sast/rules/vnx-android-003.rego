package vulnetix.rules.vnx_android_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-ANDROID-003",
	"name": "Android component exported without a permission",
	"description": "An <activity>, <activity-alias>, <service>, <receiver> or <provider> in a production AndroidManifest.xml is reachable by every app on the device and requires no permission. Exported means android:exported=\"true\", or (activity, service, receiver) an <intent-filter> with no android:exported attribute, which exports the component in an app targeting API 30 or lower (API 31+ refuses to build that manifest). Protected means android:permission, or for a provider both android:readPermission and android:writePermission. Not reported: components whose intent filters answer a platform action (android.* or com.google.android.*: the launcher entry, deep links and app links, share targets, system broadcasts, Play-services bindings), which are public by design and cannot require a permission; components with android:exported=\"false\", tools:node=\"remove\" or android:enabled=\"false\"; providers left unexported by default; manifests in debug/test source sets and test, sample, example or demo modules; XML comments. Whether the permission's protection level is strong enough, and how the component validates its input, are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-003/",
	"languages": ["android"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [926],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1427"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["android", "manifest", "exported-component", "mobile-security"],
}

_nonprod(path) if helpers.is_test_path(path)

_nonprod(path) if regex.match(`(^|/)src/(debug|androidTest|test|testFixtures|[A-Za-z]+Debug)/`, path)

_nonprod(path) if regex.match(`(?i)(^|/)([\w.]*[-_.])?(tests?|testing|samples?|examples?|demos?)([-_.][\w.-]*)?/`, path)

_component_re := `<(activity-alias|activity|service|receiver|provider)(\s|/|>|$)`

# Line i is inside an XML comment.
_in_comment(lines, i) if startswith(trim_space(lines[i]), "<!--")

_in_comment(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], "<!--")
	parts := split(lines[j], "<!--")
	not contains(parts[count(parts) - 1], "-->")
	not _closed_between(lines, j + 1, i - 1)
}

_closed_between(lines, a, b) if {
	a <= b
	some k in numbers.range(a, b)
	contains(lines[k], "-->")
}

# The element's text from its start tag on line i: {start tag, body}.
_rest(lines, i, tag) := rest if {
	text := concat("\n", array.slice(lines, i, min([count(lines), i + 80])))
	rest := substring(text, indexof(text, concat("", ["<", tag])), -1)
}

_start(rest) := ms[0] if {
	ms := regex.find_n(`^<[\w:-]+[^>]*>`, rest, 1)
	count(ms) > 0
}

_body(_, start, _) := "" if endswith(start, "/>")

_body(rest, start, tag) := b if {
	not endswith(start, "/>")
	after := substring(rest, count(start), -1)
	b := _until_close(after, tag)
}

_until_close(after, tag) := ms[0] if {
	ms := regex.find_n(concat("", [`(?s)^.*?</`, tag, `\s*>`]), after, 1)
	count(ms) > 0
} else := after

_exported(_, start, _) if regex.match(`android:exported\s*=\s*["']true["']`, start)

_exported(tag, start, body) if {
	tag != "provider"
	not contains(start, "android:exported")
	contains(body, "<intent-filter")
}

_protected(_, start) if regex.match(`android:permission\s*=\s*["'][^"']+["']`, start)

_protected("provider", start) if {
	regex.match(`android:readPermission\s*=\s*["'][^"']+["']`, start)
	regex.match(`android:writePermission\s*=\s*["'][^"']+["']`, start)
}

# An intent filter that answers a platform action is a public contract.
_public_contract(body) if regex.match(`<action\b[^>]*android:name\s*=\s*["'](android\.|com\.google\.android\.)`, body)

_inactive(start) if regex.match(`tools:node\s*=\s*["']remove["']`, start)

_inactive(start) if regex.match(`android:enabled\s*=\s*["']false["']`, start)

_name(start) := n if {
	ms := regex.find_all_string_submatch_n(`android:name\s*=\s*["']([^"']+)["']`, start, 1)
	count(ms) > 0
	n := ms[0][1]
} else := "(unnamed)"

_how(start) := "android:exported=\"true\"" if contains(start, "android:exported")

_how(start) := "an intent-filter with no android:exported (exported on API 30 and lower)" if not contains(start, "android:exported")

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(^|/)AndroidManifest\.xml$`, path)
	not _nonprod(path)
	regex.match(`<(activity|service|receiver|provider)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "<")
	m := regex.find_all_string_submatch_n(_component_re, line, 1)
	count(m) > 0
	tag := m[0][1]
	not _in_comment(lines, i)
	rest := _rest(lines, i, tag)
	start := _start(rest)
	body := _body(rest, start, tag)
	_exported(tag, start, body)
	not _protected(tag, start)
	not _public_contract(body)
	not _inactive(start)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("<%s %s> is exported (%s) and requires no permission, so any app on the device can start, bind or query it. Set android:exported=\"false\", or require a signature-level android:permission", [tag, _name(start), _how(start)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
