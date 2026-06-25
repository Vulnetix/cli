---
title: "AIBOM"
weight: 7
description: "Discover AI coding agents and AI usage, and emit a CycloneDX AI Bill of Materials."
---

The `vulnetix aibom` command discovers evidence of AI coding agents/assistants and AI usage in a project and produces an **AI Bill of Materials (AIBOM)** in CycloneDX 1.7 format.

> **This page is generated** from the detection catalog (`internal/aibom/catalog/*.json`). Run `just gen-aibom` after editing the catalog.

## What it detects

Three passes, all driven by a maintainable catalog:

- **Environment** — known AI tool / provider environment-variable *names*. Values are never read or emitted, so secrets never leak into the AIBOM.
- **Filesystem** — tool config directories, instruction files, ignore files, skills, hooks, plugins, steering, memory, prompts, agents, commands and marketplace manifests.
- **Source code** — AI SDK/framework usage per language, and the model-name literals passed to them. Model names are extracted by anchoring on the SDK parameter (`model=`, `modelId=`, `deployment_name=`), so **future / unknown model names are still captured**.
- **Commit history** — commits authored by an AI agent, identified by `Co-Authored-By` trailers, session markers (e.g. `Claude-Session:`), agent bot authors, or "Generated with <tool>" lines. Catches agent use that left no file/env/source trace.

The builtin catalog (version `2026.06.4`) covers **84 AI coding agents**, **73 AI provider services**, **2 conventions**, and **102 AI SDKs** across many languages.

{{< cards >}}
  {{< card link="supported-tools" title="Supported Agents" subtitle="Every AI coding tool & provider the catalog detects." icon="chip" >}}
  {{< card link="libraries" title="AI SDKs" subtitle="SDKs detected and the model parameters extracted." icon="code" >}}
  {{< card link="catalog-format" title="Catalog Format" subtitle="Extend or override detection with --catalog." icon="document-text" >}}
  {{< card link="../cli-reference/aibom" title="Command Reference" subtitle="vulnetix aibom flags and examples." icon="terminal" >}}
{{< /cards >}}
