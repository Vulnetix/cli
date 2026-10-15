# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_360

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-360",
	"name": "Android receiver for a system broadcast trusts the intent without checking its action",
	"description": "A BroadcastReceiver that listens for a system event (boot completed, SMS received, power connected, connectivity or package changes) acts on every intent it is handed without checking intent.getAction(). Only the system can send those broadcasts, but any installed app can deliver an intent straight to an exported receiver by component name, so the 'system event' and its extras can be forged. Reported in Java and Kotlin: the onReceive(Context, Intent) method (its parameters on one line or broken over the next three, annotations such as @NonNull read through), whose body (up to 40 lines) never reads the intent's action (getAction(), intent.action, intent?.action), of a receiver that is either (a) registered in the same file with an IntentFilter / addAction naming a system action (Intent.ACTION_*, \"android.intent.action.*\", \"android.provider.Telephony.*\", Telephony.Sms.Intents.*, *_ACTION constants), or (b) declared in an AndroidManifest.xml <receiver> whose intent-filter names an android.* system action and which is neither android:exported=\"false\" nor protected by android:permission. Not reported: receivers that check the action, receivers for the app's own custom actions only, receivers registered with RECEIVER_NOT_EXPORTED, an anonymous receiver held in a variable that is registered only with inline filters for custom actions (the system filter in the same file belongs to another receiver), non-exported or permission-protected manifest receivers, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-360/",
	"languages": ["android", "java", "kotlin"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [360],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["trust-system-event", "android", "broadcast-receiver", "cwe-360"],
}

_system_action_xml := `android:name\s*=\s*"android\.(?:intent\.action|provider\.Telephony|net\.conn|net\.wifi|bluetooth\.[\w.]*action|hardware\.usb\.action|app\.action)\.[A-Z_]+"`

# Short class names of manifest receivers reachable from other apps that
# listen for a system action.
_manifest_receivers contains name if {
	some path, content in input.file_contents
	endswith(path, "AndroidManifest.xml")
	contains(content, "<receiver")
	some m in regex.find_all_string_submatch_n(`<receiver\b([^>]*)>((?:[^<]|<[^/]|</[^r])*)</receiver>`, content, -1)
	attrs := m[1]
	not regex.match(`android:exported\s*=\s*"false"`, attrs)
	not regex.match(`android:permission\s*=`, attrs)
	regex.match(_system_action_xml, m[2])
	n := regex.find_all_string_submatch_n(`android:name\s*=\s*"([\w.$]+)"`, attrs, 1)
	count(n) > 0
	parts := split(n[0][1], ".")
	name := parts[count(parts) - 1]
}

_file_system_filter := `(?:IntentFilter\s*\(|addAction\s*\()\s*(?:Intent\.ACTION_\w+|"android\.(?:intent\.action|provider\.Telephony|net\.conn|net\.wifi|bluetooth\.[\w.]*action|hardware\.usb\.action)\.\w+"|Telephony\.Sms\.Intents\.\w+|[A-Z]\w*\.\w*ACTION\w*)`

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".kt")

_indent(line) := count(line) - count(trim_left(line, " \t"))

_body_end(lines, i) := e if {
	end := min([count(lines) - 1, i + 40])
	ind := _indent(lines[i])
	stops := [k |
		some k in numbers.range(i + 1, end)
		trim_space(lines[k]) != ""
		_indent(lines[k]) <= ind
		regex.match(`^\s*\}`, lines[k])
	]
	e := _first_or(stops, end)
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

# The named receiver class whose declaration is nearest above line i.
_owner(lines, i) := name if {
	decls := [[k, m[0][1]] |
		some k in numbers.range(0, i)
		contains(lines[k], "BroadcastReceiver")
		m := regex.find_all_string_submatch_n(`\bclass\s+(\w+)\s*(?:extends\s+|:\s*)BroadcastReceiver\b`, lines[k], 1)
		count(m) > 0
	]
	count(decls) > 0
	last := decls[count(decls) - 1]
	not _anonymous_between(lines, last[0], i)
	name := last[1]
}

_anonymous_between(lines, a, b) if {
	some k in numbers.range(a + 1, b)
	regex.match(`new\s+BroadcastReceiver\s*\(|object\s*:\s*BroadcastReceiver\s*\(`, lines[k])
}

_system_event(_, content, lines, i) if {
	not _custom_only(content, lines, i)
	regex.match(_file_system_filter, content)
	not contains(content, "RECEIVER_NOT_EXPORTED")
}

_system_event(_, _, lines, i) if {
	name := _owner(lines, i)
	_manifest_receivers[name]
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "onReceive")
	contains(content, "BroadcastReceiver")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "onReceive")

	# the signature may break its parameters over the next three lines
	# annotations on the parameters (@NonNull Context context) are dropped
	sig := regex.replace(concat(" ", array.slice(lines, i, i + 4)), `@[\w.]+(?:\([^()]*\))?\s+`, "")
	m := regex.find_all_string_submatch_n(`^[^\n]*?(?:\bvoid|\bfun)\s+onReceive\s*\(\s*(?:final\s+)?(?:\w+\s*:\s*)?(?:\w+\s+)?\w*\s*(?::\s*Context\??)?\s*,\s*(?:final\s+)?(?:Intent\s+(\w+)|(\w+)\s*:\s*Intent\??)`, sig, 1)
	count(m) > 0
	not helpers.is_comment_line(line)
	param := concat("", [m[0][1], m[0][2]])
	_system_event(path, content, lines, i)
	e := _body_end(lines, i)
	body := concat("\n", array.slice(lines, i + 1, e))
	not regex.match(concat("", [`getAction\s*\(|\b`, param, `\s*(?:!!)?\??\.action\b`]), body)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("onReceive acts on a system broadcast without checking %s.getAction(): any app can send this exported receiver a forged intent by component name. Check the action (and validate extras) before acting, or register it RECEIVER_NOT_EXPORTED", [param]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The anonymous receiver whose onReceive is on line i is held in a variable
# (val syncReceiver = object : BroadcastReceiver() / BroadcastReceiver r = new BroadcastReceiver()).
_anon_var(lines, i) := name if {
	some k in numbers.range(max([0, i - 3]), i)
	m := regex.find_all_string_submatch_n(`\b(\w+)\s*(?::\s*BroadcastReceiver\s*)?=\s*(?:new\s+BroadcastReceiver\s*\(|object\s*:\s*BroadcastReceiver\s*\()`, lines[k], 1)
	count(m) > 0
	name := m[0][1]
}

# That variable is registered only with inline filters for the app's own
# actions: the system filter in the same file belongs to another receiver.
_custom_only(content, lines, i) if {
	name := _anon_var(lines, i)
	regs := regex.find_all_string_submatch_n(concat("", [`registerReceiver\(\s*(?:\w+\s*,\s*)?`, name, `\s*,\s*([^\n]*)`]), content, -1)
	count(regs) > 0
	every r in regs {
		regex.match(`^(?:new\s+)?IntentFilter\(\s*"[^"]+"\s*\)`, r[1])
		not regex.match(`^(?:new\s+)?IntentFilter\(\s*"android\.`, r[1])
	}
}
