---
title: "VNX-LLM-004 – User Input Directly in LLM System Prompt"
description: "Detects user-controlled input interpolated directly into LLM system prompts via f-strings or string concatenation, enabling prompt injection attacks that override system instructions or leak confidential context."
---

## Overview

Large language model APIs separate instructions from user content using a role-based message structure: a `system` role message defines the model's behaviour and constraints, while a `user` role message contains the end-user's input. When user-controlled data is interpolated into the system prompt — using Python f-strings, string concatenation, or LangChain `PromptTemplate.from_template()` with an f-string — an attacker can inject instructions that override the system prompt's intended behaviour, leak its contents, or manipulate the model into performing unintended actions. This is a form of CWE-77 (Improper Neutralisation of Special Elements used in a Command).

This rule flags three patterns: system role message dicts where the content value appears to be constructed with an f-string or concatenated with a user/request/input/query variable; Anthropic `system=` keyword arguments constructed with an f-string; and LangChain `PromptTemplate.from_template()` calls with an f-string argument. All three patterns indicate that the boundary between instructions and user content has been collapsed.

The system prompt often contains confidential instructions — persona definitions, business rules, tool configurations, or sensitive context about the application's internal workings. Once an attacker can inject into the system prompt, they can direct the model to reveal these instructions or to ignore all prior constraints entirely.

**Severity:** High | **CWE:** [CWE-77 – Improper Neutralisation of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)

## Why This Matters

Prompt injection is to LLM applications what SQL injection was to database-backed web applications: a fundamental input-handling flaw that occurs when instructions and data share the same channel without proper separation. The attack surface is particularly large because natural language has no formal escaping mechanism — there is no equivalent of parameterised queries that reliably separates user content from model instructions.

A system prompt containing business-sensitive rules, API keys embedded as context, or customer data summaries becomes a target. An attacker who can control even a small portion of the system prompt can instruct the model to prefix every response with the full system prompt content, effectively leaking it. More dangerously, they can disable safety guardrails, override persona constraints, or instruct the model to take actions (via tool calls or agentic steps) that the system prompt was designed to prohibit.

Real-world prompt injection attacks have been demonstrated against deployed products including Microsoft Copilot, Google Bard plugins, and numerous LLM-powered chatbots. The attack requires no technical exploitation skill — just crafted natural language.

## What Gets Flagged

```python
# FLAGGED: user input interpolated into system role message
messages = [
    {"role": "system", "content": f"You are a helpful assistant. The user's name is {user_input}."},
    {"role": "user", "content": user_message}
]

# FLAGGED: Anthropic system prompt with f-string
response = client.messages.create(
    model="claude-3-opus-20240229",
    system=f"Answer questions about {user_context}. Be concise.",
    messages=[{"role": "user", "content": prompt}]
)

# FLAGGED: LangChain PromptTemplate with f-string
template = PromptTemplate.from_template(f"You are a {role} assistant. Answer: {{question}}")
```

## Remediation

1. **Keep system prompts entirely static.** Write the system prompt as a literal string with no user-supplied values. All dynamic context should go into the `user` role message.

2. **Use LangChain template variables** (`{variable}`) instead of Python f-strings when dynamic content is required. Template variables are substituted after the template is parsed and are treated as data, not instructions, by the chain.

3. **Pass user input only in the `user` role.** If user context must appear in the prompt, include it as clearly demarcated data in the user message, not as instruction-level content in the system message.

4. **Validate and sanitise user input** before including it in any prompt position, rejecting or escaping strings that contain injection-attempt patterns (e.g., "ignore previous instructions", "system:", role-switching markers).

```python
# SAFE: static system prompt, user content in user role only
SYSTEM_PROMPT = "You are a helpful customer support assistant for Acme Corp. Answer only questions about our products."

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message}  # user input here, not in system
    ]
)
```

```python
# SAFE: LangChain template variables (not f-strings)
from langchain.prompts import PromptTemplate

template = PromptTemplate.from_template(
    "Answer the following question about {topic}: {question}"
)
chain = template | llm
result = chain.invoke({"topic": topic, "question": user_question})
```

## References

- [OWASP LLM Top 10: LLM01 – Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS: LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)
- [LangChain Security Best Practices](https://python.langchain.com/docs/security)
- [CWE-77: Improper Neutralisation of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)
- [CAPEC-137: Parameter Injection](https://capec.mitre.org/data/definitions/137.html)
