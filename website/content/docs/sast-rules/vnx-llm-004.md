---
title: "VNX-LLM-004 – User Input Directly in LLM System Prompt"
description: "Reports user input read from an HTTP request, or a variable named as user data, interpolated into an LLM system prompt (system role, system= argument, SystemMessage, PromptTemplate.from_template, a system prompt builder)."
---

## Overview

Large language model APIs separate instructions from user content using a role-based message structure: a `system` role message defines the model's behaviour and constraints, while a `user` role message contains the end-user's input. When user-controlled data is interpolated into the system prompt — using Python f-strings, string concatenation, or LangChain `PromptTemplate.from_template()` with an f-string — an attacker can inject instructions that override the system prompt's intended behaviour, leak its contents, or manipulate the model into performing unintended actions. This is a form of CWE-77 (Improper Neutralisation of Special Elements used in a Command).

This rule flags a value read from an HTTP request, or a variable named as user data, interpolated into a system prompt: a `role: system` message, an Anthropic or Vercel AI SDK `system` argument, a LangChain `SystemMessage` or `PromptTemplate.from_template(f"...")`, or a line inside a function or variable named as a system prompt. Each collapses the boundary between instructions and user content.

The system prompt often contains confidential instructions — persona definitions, business rules, tool configurations, or sensitive context about the application's internal workings. Once an attacker can inject into the system prompt, they can direct the model to reveal these instructions or to ignore all prior constraints entirely.

**Severity:** High | **CWE:** [CWE-77 – Improper Neutralisation of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)

## Why This Matters

Prompt injection is to LLM applications what SQL injection was to database-backed web applications: a fundamental input-handling flaw that occurs when instructions and data share the same channel without proper separation. The attack surface is particularly large because natural language has no formal escaping mechanism — there is no equivalent of parameterised queries that reliably separates user content from model instructions.

A system prompt containing business-sensitive rules, API keys embedded as context, or customer data summaries becomes a target. An attacker who can control even a small portion of the system prompt can instruct the model to prefix every response with the full system prompt content, effectively leaking it. More dangerously, they can disable safety guardrails, override persona constraints, or instruct the model to take actions (via tool calls or agentic steps) that the system prompt was designed to prohibit.

Real-world prompt injection attacks have been demonstrated against deployed products including Microsoft Copilot, Google Bard plugins, and numerous LLM-powered chatbots. The attack requires no technical exploitation skill — just crafted natural language.

## What Gets Flagged

User input read from an HTTP request, or a variable named as user data (`user_name`, `userName`, `user_profile`, `user_input`, ...), interpolated into a system prompt: a `role: system` message, Anthropic/Vercel AI SDK `system=`/`system:`, LangChain `SystemMessage`, `("system", ...)` tuples, `PromptTemplate.from_template(f"...")`, or a line inside a function or variable named as a system prompt.

```python
# FLAGGED: request value in the system role
nickname = request.args["nickname"]
messages=[{"role": "system", "content": f"You are a concierge. Address the customer as {nickname}."}]
```

```python
# FLAGGED: Anthropic system prompt with a user profile
system=f"Answer as a support agent. Customer profile: {user_profile}",
```

```typescript
// FLAGGED: user name in a system prompt builder
export function buildSystemPrompt (userName?: string) {
  const greeting = userName ? `\nThe customer you are chatting with is ${userName}.` : '';
```

Not flagged: a static system prompt, server-side values such as the date or a tool list in it, and LangChain template variables filled at invoke time.

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
