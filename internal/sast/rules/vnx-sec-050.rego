package vulnetix.rules.vnx_sec_050

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-050",
	"name": "Google Gemini / Vertex AI / PaLM API key",
	"description": "Reports a Google API key (AIza followed by 35 characters) used for the generative AI APIs: the key must sit on a line, or within eight lines of one, that names Gemini, PaLM, Vertex AI, the generativelanguage.googleapis.com endpoint or a Google GenAI SDK (google.generativeai, google-genai, @google/generative-ai, generative-ai-go). Such keys are billed per request and are scraped from public repositories. Not reported: a key inside a Firebase web config (authDomain, *.firebaseapp.com, messagingSenderId nearby), which is public and App Check-guarded even when the app reaches Gemini through Vertex AI in Firebase; the bare word palm (place names) as context; AIza keys with no generative-AI context (Maps, Firebase web config and generic GCP keys are reported by VNX-SEC-005/VNX-SEC-170 and the context rules), keys read from the environment, placeholder bodies, and test, fixture or vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-050/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "google", "gemini", "ai", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_-])(AIza[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9_-]|$)`

# Names of the generative AI products, endpoint and SDKs.
_context := `(?i:gemini|generativelanguage|generative[-_ ]?ai|\bgenai\b|\bpalm[-_ ]?(?:api|2)\b|text-bison|chat-bison|vertex[-_ ]?ai|aiplatform\.googleapis|ai\.google\.dev|makersuite|aistudio)|\bPaLM\b`

# A Firebase web config (authDomain, *.firebaseapp.com) carries a public,
# App Check-guarded key even when the app calls Gemini through Vertex AI in
# Firebase; that key is left to the generic Google key rules.
_firebase_config := `authDomain|firebaseapp\.com|messagingSenderId`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "AIza")
	regex.match(_context, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "AIza")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(substring(token, 4, -1))
	window := concat("\n", array.slice(lines, max([0, i - 8]), i + 9))
	regex.match(_context, window)
	not regex.match(_firebase_config, window)
	finding := {
		"rule_id": metadata.id,
		"message": "Google API key used for Gemini / Vertex AI / PaLM found; delete it in the Google Cloud console or AI Studio and load the replacement from a secret store",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
