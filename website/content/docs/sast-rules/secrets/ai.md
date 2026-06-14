---
title: "Secrets — AI / LLM Providers"
description: "OpenAI, Anthropic, Google Gemini, Hugging Face, Cohere, Mistral and other AI provider keys."
weight: 3
---

OpenAI, Anthropic, Google Gemini, Hugging Face, Cohere, Mistral and other AI provider keys.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-086"></a>VNX-SEC-086 | Cohere API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-087"></a>VNX-SEC-087 | Mistral AI API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-251"></a>VNX-SEC-251 | OpenAI classic API key (sk-) | Critical | keyword + regex |
| <a id="vnx-sec-252"></a>VNX-SEC-252 | OpenAI legacy API key (sk- 48 char) | Critical | keyword + regex |
| <a id="vnx-sec-253"></a>VNX-SEC-253 | OpenAI organization ID (org-) | Medium | keyword + regex |
| <a id="vnx-sec-254"></a>VNX-SEC-254 | OpenAI project ID (proj_) | Medium | keyword + regex |
| <a id="vnx-sec-255"></a>VNX-SEC-255 | Azure OpenAI API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-256"></a>VNX-SEC-256 | Replicate API token (r8_) | Critical | keyword + regex |
| <a id="vnx-sec-257"></a>VNX-SEC-257 | Together AI API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-258"></a>VNX-SEC-258 | Groq API key (gsk_) | Critical | keyword + regex |
| <a id="vnx-sec-259"></a>VNX-SEC-259 | Perplexity API key (pplx-) | Critical | keyword + regex |
| <a id="vnx-sec-260"></a>VNX-SEC-260 | DeepSeek API key (sk-) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-261"></a>VNX-SEC-261 | Stability AI API key (sk-) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-262"></a>VNX-SEC-262 | ElevenLabs API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-263"></a>VNX-SEC-263 | ElevenLabs API key (sk_ prefix) | Critical | keyword + regex |
| <a id="vnx-sec-264"></a>VNX-SEC-264 | AssemblyAI API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-265"></a>VNX-SEC-265 | Deepgram API key (Token) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-266"></a>VNX-SEC-266 | Pinecone API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-267"></a>VNX-SEC-267 | Pinecone API key (pckey_) | Critical | keyword + regex |
| <a id="vnx-sec-268"></a>VNX-SEC-268 | Weaviate API key | High | keyword + regex + entropy |
| <a id="vnx-sec-269"></a>VNX-SEC-269 | Qdrant API key | High | keyword + regex + entropy |
| <a id="vnx-sec-270"></a>VNX-SEC-270 | LangSmith personal API key (lsv2_pt_) | Critical | keyword + regex |
| <a id="vnx-sec-271"></a>VNX-SEC-271 | LangSmith service API key (lsv2_sk_) | Critical | keyword + regex |
| <a id="vnx-sec-272"></a>VNX-SEC-272 | LangChain/LangSmith legacy API key (ls__) | High | keyword + regex |
| <a id="vnx-sec-273"></a>VNX-SEC-273 | Weights & Biases API key | High | keyword + regex + entropy |
| <a id="vnx-sec-274"></a>VNX-SEC-274 | CometML API key | High | keyword + regex + entropy |
| <a id="vnx-sec-275"></a>VNX-SEC-275 | Clarifai personal access token | High | keyword + regex + entropy |
| <a id="vnx-sec-276"></a>VNX-SEC-276 | Scale AI API key | High | keyword + regex + entropy |
| <a id="vnx-sec-277"></a>VNX-SEC-277 | Anyscale API key (esecret_) | Critical | keyword + regex |
| <a id="vnx-sec-278"></a>VNX-SEC-278 | Fireworks AI API key (fw_) | Critical | keyword + regex |
| <a id="vnx-sec-279"></a>VNX-SEC-279 | OctoAI API token | High | keyword + regex + entropy |
| <a id="vnx-sec-280"></a>VNX-SEC-280 | Voyage AI API key (pa-) | Critical | keyword + regex |
| <a id="vnx-sec-281"></a>VNX-SEC-281 | Jina AI API key (jina_) | Critical | keyword + regex |
| <a id="vnx-sec-282"></a>VNX-SEC-282 | AI21 Labs API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-283"></a>VNX-SEC-283 | Aleph Alpha API token | High | keyword + regex + entropy |
| <a id="vnx-sec-284"></a>VNX-SEC-284 | NVIDIA NGC API key (nvapi-) | Critical | keyword + regex |
| <a id="vnx-sec-285"></a>VNX-SEC-285 | Hugging Face fine-grained token (hf_oauth/api) | Critical | keyword + regex |
| <a id="vnx-sec-286"></a>VNX-SEC-286 | Modal token ID (ak-) | High | keyword + regex |
| <a id="vnx-sec-287"></a>VNX-SEC-287 | Modal token secret (as-) | Critical | keyword + regex |
| <a id="vnx-sec-288"></a>VNX-SEC-288 | Baseten API key | High | keyword + regex + entropy |
| <a id="vnx-sec-289"></a>VNX-SEC-289 | RunPod API key | Critical | keyword + regex |
| <a id="vnx-sec-290"></a>VNX-SEC-290 | Lambda Labs Cloud API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-291"></a>VNX-SEC-291 | Cerebras API key (csk-) | Critical | keyword + regex |
| <a id="vnx-sec-292"></a>VNX-SEC-292 | Replicate API token (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-293"></a>VNX-SEC-293 | Voyage AI API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-294"></a>VNX-SEC-294 | Together AI API key (40 hex) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-295"></a>VNX-SEC-295 | Fireworks AI API key (fw- dash form) | Critical | keyword + regex |
| <a id="vnx-sec-296"></a>VNX-SEC-296 | Groq API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-297"></a>VNX-SEC-297 | Mistral API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-298"></a>VNX-SEC-298 | Hugging Face token (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-299"></a>VNX-SEC-299 | Anthropic API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-300"></a>VNX-SEC-300 | Perplexity API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-301"></a>VNX-SEC-301 | DeepSeek API key (sk- standalone) | High | keyword + regex + entropy |
| <a id="vnx-sec-302"></a>VNX-SEC-302 | Cerebras API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-303"></a>VNX-SEC-303 | AssemblyAI API key (32 hex assignment) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-304"></a>VNX-SEC-304 | Deepgram API key (Token header) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-305"></a>VNX-SEC-305 | LangChain endpoint API key (assignment context) | High | keyword + regex + entropy |
| <a id="vnx-sec-306"></a>VNX-SEC-306 | Stability AI API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-307"></a>VNX-SEC-307 | NVIDIA NGC API key (legacy hex) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-308"></a>VNX-SEC-308 | ElevenLabs API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-309"></a>VNX-SEC-309 | Qdrant API key (JWT form) | High | keyword + regex + entropy |
| <a id="vnx-sec-310"></a>VNX-SEC-310 | CometML API key (assignment context) | High | keyword + regex + entropy |
| <a id="vnx-sec-311"></a>VNX-SEC-311 | RunPod API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-312"></a>VNX-SEC-312 | Baseten API key (assignment context) | High | keyword + regex + entropy |
| <a id="vnx-sec-313"></a>VNX-SEC-313 | Jina AI API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-314"></a>VNX-SEC-314 | Anyscale API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-315"></a>VNX-SEC-315 | AI21 Labs API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-316"></a>VNX-SEC-316 | Pinecone API key (assignment context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-317"></a>VNX-SEC-317 | Weaviate API key (assignment context) | High | keyword + regex + entropy |
| <a id="vnx-sec-318"></a>VNX-SEC-318 | OctoAI token (assignment context) | High | keyword + regex + entropy |
| <a id="vnx-sec-319"></a>VNX-SEC-319 | Lambda Labs API key (lambda. prefix) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-320"></a>VNX-SEC-320 | Clarifai PAT (assignment context) | High | keyword + regex + entropy |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
