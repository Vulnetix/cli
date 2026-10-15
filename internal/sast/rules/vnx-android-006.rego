package vulnetix.rules.vnx_android_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-ANDROID-006",
	"name": "Android credential hard-coded in a string resource",
	"description": "A <string> (or <item type=\"string\">) in an Android values resource file (res/values*/..xml, including strings.xml, secrets.xml and qualified values-xx folders) is named as a credential (api key, secret, token, password, passphrase, passcode, private/signing/encryption/licence key, credential) and holds a literal that looks like one: at least 8 characters, no whitespace, not a resource or ${build} reference, not a URL. Resource strings are compiled into resources.arsc and read back out of the APK by apktool. Not reported: UI text (names with hint, label, title, prompt, error, message, button, action, forgot/reset/change, description, format, pref/preference and similar, or values that are a sentence, a Title-case word, a snake_case identifier or end in ':'/'?'), placeholders (YOUR_..., ..._HERE, changeme, xxxx, empty), the Firebase/Facebook client identifiers that are public by design (google_api_key, google_crash_reporting_api_key, facebook_client_token), XML comments, layouts and XML outside values folders, and test source sets. Tokens with a known provider shape are also reported by the generated secret rules wherever they appear.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-006/",
	"languages": ["android"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["android", "hardcoded-credentials", "secrets", "mobile-security"],
}

_values_file(path) if regex.match(`(^|/)[\w-]*[rR]es[\w-]*/values[\w+-]*/[^/]+\.xml$`, path)

_nonprod(path) if helpers.is_test_path(path)

_nonprod(path) if regex.match(`(^|/)src/(androidTest|test|testFixtures)/`, path)

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

_elem_re := `<(string|item)\b([^>]*)>([^<]*)</(string|item)>`

_cred_name := `(?i)(api_?key|apikey|secret|private_?key|access_?key|signing_?key|encryption_?key|licen[cs]e_?key|token|passw(or)?d|passwd|passphrase|pass_?code|pwd|credential)`

_ui_name := `(?i)(hint|label|title|prompt|error|_err|err_|msg|message|desc|summary|button|btn|action|menu|caption|placeholder|forgot|reset|change|confirm|enter|show|hide|toggle|visib|invalid|wrong|incorrect|required|requirement|empty|missing|header|dialog|tab_|screen|activity|tooltip|instruction|pref|_url|url_|uri|endpoint|host|regex|pattern|scope|format|length|strength|policy|expir|_type|type_|text|notice|warning|success|fail|help|question|sample|example|dummy)`

_public_ids := {"google_api_key", "google_crash_reporting_api_key", "facebook_client_token"}

_placeholder := `(?i)^(your|insert|replace|enter|todo|tbd|fixme|changeme|change_me|placeholder|dummy|sample|example|none|null|undefined|default|secret|password|token|api_?key)|(?i)(your_|_here|xxxx|\*\*\*\*)|^(x+|X+|0+|\.+|-+|_+)$`

_secret_like(v) if {
	count(v) >= 8
	regex.match(`^[^\s@?$%][^\s]*$`, v)
	not contains(v, "://")
	not regex.match(_placeholder, v)
	not regex.match(`^[A-Z][a-z]+([A-Z][a-z0-9]+)*$`, v) # a Title-case or CamelCase word
	not regex.match(`^[a-z]+(_[a-z0-9]+)+$`, v) # a snake_case identifier
	not regex.match(`[:?…]$`, v)
}

_attr(attrs, name) := v if {
	ms := regex.find_all_string_submatch_n(concat("", [`\b`, name, `\s*=\s*["']([^"']*)["']`]), attrs, 1)
	count(ms) > 0
	v := ms[0][1]
}

_string_elem("string", _)

_string_elem("item", attrs) if _attr(attrs, "type") == "string"

findings contains finding if {
	some path, content in input.file_contents
	_values_file(path)
	not _nonprod(path)
	contains(content, "<resources")
	regex.match(_cred_name, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "name")
	not _in_comment(lines, i)
	some m in regex.find_all_string_submatch_n(_elem_re, line, -1)
	m[1] == m[4]
	_string_elem(m[1], m[2])
	name := _attr(m[2], "name")
	regex.match(_cred_name, name)
	not regex.match(_ui_name, name)
	not lower(name) in _public_ids
	value := trim_space(m[3])
	value != name
	_secret_like(value)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("String resource %q holds a hard-coded credential; resources are compiled into the APK and recovered with apktool. Rotate it, keep it out of the repository, and fetch it at runtime from your backend (or inject a scoped, restricted key at build time from a CI secret)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
