package vulnetix.rules.vnx_android_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-ANDROID-001",
	"name": "Android app shipped debuggable or with unrestricted backup",
	"description": "A production Android build is made debuggable, or lets the platform back up all of its private data. Reported: android:debuggable=\"true\" in an AndroidManifest.xml; debuggable true / isDebuggable = true inside the release build type of build.gradle or build.gradle.kts; and android:allowBackup=\"true\" on an <application> that declares neither android:fullBackupContent nor android:dataExtractionRules, so the token store and databases go into every backup. Not reported: false or ${placeholder} values, an allowBackup with backup rules (the rules decide what is excluded), the debug and other build types, manifests in debug/test source sets (src/debug, src/androidTest, src/test), test, sample, example and demo modules, XML comments, and the attribute text in Java/Kotlin strings. An omitted allowBackup (which defaults to true) is not reported. Exported components are VNX-ANDROID-003 and cleartext traffic is VNX-ANDROID-005.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-001/",
	"languages": ["android"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [489, 921],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1409"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["android", "manifest", "debuggable", "backup", "mobile-security"],
}

_manifest(path) if regex.match(`(^|/)AndroidManifest\.xml$`, path)

_gradle(path) if regex.match(`(^|/)build\.gradle(\.kts)?$`, path)

# Not the shipped app: debug/test source sets, test fixtures, and modules
# named as tests, samples, examples or demos.
_nonprod(path) if helpers.is_test_path(path)

_nonprod(path) if regex.match(`(^|/)src/(debug|androidTest|test|testFixtures|[A-Za-z]+Debug)/`, path)

_nonprod(path) if regex.match(`(?i)(^|/)([\w.]*[-_.])?(tests?|testing|samples?|examples?|demos?)([-_.][\w.-]*)?/`, path)

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── AndroidManifest.xml ─────────────────────────────────────────────────

_attr_re := `android:(debuggable|allowBackup)\s*=\s*["']true["']`

# Line i is inside an XML comment: it opens one, or a comment opened in the
# 30 lines above has not been closed before it.
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

# The <application ...> start tag that holds line i.
_app_tag(lines, i) := tag if {
	opens := [j | some j in numbers.range(max([0, i - 40]), i); contains(lines[j], "<application")]
	count(opens) > 0
	s := max(opens)
	text := concat("\n", array.slice(lines, s, min([count(lines), s + 60])))
	ms := regex.find_n(`<application\b[^>]*>`, text, 1)
	count(ms) > 0
	tag := ms[0]
}

_backup_rules(lines, i) if {
	tag := _app_tag(lines, i)
	regex.match(`android:(fullBackupContent|dataExtractionRules)\s*=`, tag)
}

_reportable("debuggable", _, _)

_reportable("allowBackup", lines, i) if not _backup_rules(lines, i)

_message("debuggable") := "android:debuggable=\"true\" ships a debuggable app: anyone with adb can attach a debugger, read memory and run code as the app. Remove the attribute and let the build type set it (release builds are not debuggable)"

_message("allowBackup") := "android:allowBackup=\"true\" with no android:fullBackupContent or android:dataExtractionRules backs up all private data (tokens, databases, shared preferences) to device-transfer and cloud backups. Set it to false, or add backup rules that exclude sensitive files"

findings contains finding if {
	some path, content in input.file_contents
	_manifest(path)
	not _nonprod(path)
	regex.match(_attr_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "true")
	some m in regex.find_all_string_submatch_n(_attr_re, line, -1)
	attr := m[1]
	not _in_comment(lines, i)
	_reportable(attr, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _message(attr),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── build.gradle / build.gradle.kts ─────────────────────────────────────

_gradle_debuggable_re := `^\s*(debuggable\s*(=\s*)?\(?\s*true\b|isDebuggable\s*=\s*true\b)`

_release_opener_re := `(\brelease\b|"release")\s*\)?\s*\{\s*$`

# The nearest line above with a smaller indent opens the enclosing block.
_in_release_block(lines, i) if {
	regex.match(_gradle_debuggable_re, lines[i])
	i > 0
	ind := _indent(lines[i])
	cands := [j |
		some j in numbers.range(max([0, i - 25]), i - 1)
		trim_space(lines[j]) != ""
		not helpers.is_comment_line(lines[j])
		_indent(lines[j]) < ind
	]
	count(cands) > 0
	regex.match(_release_opener_re, lines[max(cands)])
}

# release { debuggable true } on one line
_in_release_block(lines, i) if {
	regex.match(`(\brelease\b|"release")\s*\)?\s*\{[^}]*\b(debuggable\s*(=\s*)?\(?\s*true\b|isDebuggable\s*=\s*true\b)`, lines[i])
}

findings contains finding if {
	some path, content in input.file_contents
	_gradle(path)
	not _nonprod(path)
	contains(content, "ebuggable")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ebuggable")
	not helpers.is_comment_line(line)
	_in_release_block(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The release build type is made debuggable: the shipped APK accepts a debugger, so anyone with adb can read its memory and run code as the app. Remove debuggable/isDebuggable from the release build type",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
