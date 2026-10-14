package vulnetix.rules.vnx_llm_003

import rego.v1

import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-LLM-003",
	"name": "Hardcoded LLM API key",
	"description": "Reports an LLM provider API key written into a file: an Anthropic key (sk-ant-api03-/sk-ant-admin01- with its full-length body), an OpenAI project, service-account or admin key (sk-proj-, sk-svcacct-, sk-admin-) or classic key (sk-...T3BlbkFJ...), anywhere in a line; and a high-entropy literal of 20+ characters assigned to a provider-named key variable (OPENAI_API_KEY, anthropicApiKey, COHERE_API_KEY, GROQ_API_KEY, MISTRAL_API_KEY, GEMINI_API_KEY, ...) or passed as api_key/apiKey to a provider client constructor (OpenAI, Anthropic, Groq, Mistral, Cohere, ChatOpenAI, ...). The snippet is redacted. Not reported: keys read from the environment or a secrets manager, placeholders (your-key-here, xxxx, REPLACE, EXAMPLE), low-entropy strings, `sk-` inside longer identifiers (task-, desk-), Stripe sk_live_ keys, and test, fixture and vendored paths. Overlaps the generated provider rules VNX-SEC-018/048/049/251/252/299; this rule is the LLM-focused view.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-003/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "llm", "ai-security", "credentials"],
}

_keywords := ["sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-", "t3blbkfj", "api_key", "apikey"]

# One regex over the whole file, then over each line, before the token
# patterns: "api_key" alone is in most configuration code.
_gate := concat("", [`sk-(?:ant-|proj-|svcacct-|admin-)|T3BlbkFJ|(?i:`, _providers, `\w*?_?api_?key|\b(?:Azure|Async)?(?:OpenAI|Anthropic|Groq|Mistral\w*|Cohere\w*|ClientV2|Together|Replicate|Chat\w+)\s*\(.*api_?key)`])

_prefixed := [
	`(?:^|[^\w-])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})`,
	`(?:^|[^\w-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})`,
	`(?:^|[^\w-])(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})`,
]

_providers := `(?:openai|anthropic|claude|gemini|google_?ai|cohere|mistral|groq|together(?:_?ai)?|perplexity|pplx|deepseek|xai|grok|fireworks|replicate|huggingface|ai21|voyage|llm)`

_assigned := [
	concat("", [`(?i)\b`, _providers, "\\w*?_?api_?key\\b[\"']?\\s*[:=]\\s*[\"'`]?([A-Za-z0-9_\\-]{20,})[\"'`]?"]),
	"(?i)\\b(?:OpenAI|AzureOpenAI|AsyncOpenAI|Anthropic|AsyncAnthropic|Groq|Mistral|MistralClient|Cohere|CohereClient|ClientV2|ChatOpenAI|ChatAnthropic|ChatGroq|ChatMistralAI|Together|Replicate)\\s*\\(\\s*\\{?[^)]*?\\b(?:api_?key|apiKey)\\s*[:=]\\s*[\"'`]([A-Za-z0-9_\\-]{20,})[\"'`]",
]

_token(line) := t if {
	some p in _prefixed
	m := regex.find_all_string_submatch_n(p, line, 1)
	count(m) > 0
	t := m[0][1]
}

_token(line) := t if {
	some p in _assigned
	m := regex.find_all_string_submatch_n(p, line, 1)
	count(m) > 0
	t := m[0][1]
	regex.match(`[0-9]`, t)
	regex.match(`[A-Za-z]`, t)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	secrets.has_keyword(content, _keywords)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	secrets.has_keyword(line, _keywords)
	regex.match(_gate, line)
	token := _token(line)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded LLM provider API key; revoke and rotate it at the provider, then load it from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
