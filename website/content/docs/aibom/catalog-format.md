---
title: "Catalog Format"
weight: 3
description: "The detection catalog schema, and how to extend or override it with --catalog."
---

All AIBOM detection is driven by a declarative catalog so it can be maintained over time without code changes. The builtin catalog is embedded in the binary (`internal/aibom/catalog/*.json`). You can extend or replace it at runtime:

```bash
vulnetix aibom --catalog ./my-rules.json          # merge over the builtin (override by id)
vulnetix aibom --catalog ./only.json --no-builtin-catalog   # replace entirely
```

A catalog file is JSON with any of three top-level arrays: `tools`, `libraries`, `model_families`.

## Tool entry

```jsonc
{
  "id": "cursor",                       // unique id (override key)
  "name": "Cursor",
  "vendor": "Anysphere",
  "type": "cli-agent | ide | ide-extension | service | convention",
  "homepage": "https://cursor.com",
  "env": ["CURSOR_*"],                  // env var NAMES (exact, or globs with *). Values are never read.
  "paths": {                            // category -> repo-relative path globs (* , ** , ? supported)
    "config":       [".cursor/**"],
    "instructions": [".cursorrules"],
    "ignore":       [".cursorignore"],
    "skills":       [".cursor/skills/**"]
    // also: agents, commands, hooks, plugins, steering, memory, prompts, marketplace
  },
  "model_config_extractors": [          // optional: pull model names from this tool's config files
    {"file_glob": ".cursor/config.json", "json_key": "model"}
    // or: {"file_glob": "...", "pattern": "regex-with-one-capture-group"}
  ],
  "commit_patterns": [                   // optional: identify commits authored by this agent
    "(?i)co-authored-by:\\s*cursor\\b"   // matched against author/committer identity + message
  ]
}
```

A tool needs at least one **primary** (tool-specific) path, env/home, or commit hit to be reported. Cross-tool convention files (`AGENTS.md`, `.mcp.json`) are surfaced only through dedicated `type: "convention"` entries, so a single shared file does not light up every tool.

## Library entry

```jsonc
{
  "id": "openai-python",
  "name": "openai",
  "provider": "OpenAI",
  "languages": ["python"],             // canonical ecosystem keys (javascript covers ts/js)
  "purl_names": {"pypi": "openai"},    // ecosystem -> package name (for the component purl)
  "import_patterns": ["(?m)^\\s*(?:from|import)\\s+openai\\b"],   // confirm the SDK is used
  "model_extractors": [
    {"param": "model", "pattern": "\\bmodel\\s*=\\s*[\"']([^\"']+)[\"']", "task": "chat"}
  ]
}
```

Every `model_extractors[].pattern` must have **exactly one capture group** — the model-name literal. Anchoring on the parameter (not the value) is what makes unknown / future model names detectable.

## Model family

Family hints map a model-name prefix to a provider/family. They only enrich confidence — an unknown literal is still emitted.

```jsonc
{"prefix_regex": "^claude-", "provider": "Anthropic", "family": "Claude"}
```

All patterns are Go RE2 (no backreferences/lookaround). The catalog is validated (every pattern compiles, every extractor has a capture group) at load time and by `just gen-aibom`.
