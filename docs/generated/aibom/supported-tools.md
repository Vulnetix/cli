---
title: "Supported Agents & Providers"
weight: 1
description: "Every AI coding agent, provider service and convention the AIBOM detector recognises."
---

Each entry below is detected by the environment and filesystem passes. The **Detection signals** column lists the catalog rules — environment-variable names and repo-relative path globs.

> Generated from the catalog. To add or refine a tool, edit `internal/aibom/catalog/tools.json` and run `just gen-aibom`.

| Tool | Vendor | Type | Detection signals |
|------|--------|------|-------------------|
| AdaL | AdaL | `cli-agent` | config: `.adal/**`<br>instructions: `AGENTS.md`<br>skills: `.adal/skills/**` |
| Aider | Aider | `cli-agent` | env: `AIDER_*`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`<br>config: `.aider/**`, `.aider.conf.yml`<br>ignore: `.aiderignore`<br>memory: `.aider.chat.history.md`, `.aider.input.history`<br>skills: `.aider/skills/**`<br>commit: `(?i)co-authored-by:\s*aider\s*\([^)]*\)\s*<aider@aider\.chat>`, `(?i)<aider@aider\.chat>` |
| Amp | Sourcegraph | `cli-agent` | env: `AMP_API_KEY`, `AMP_SETTINGS_FILE`, `AMP_TOOLBOX`, `AMP_LOG_LEVEL`, `AMP_FORCE_BEL`, `AMP_SKIP_UPDATE_CHECK`<br>config: `.amp/**`, `.amp/settings.json`, `.amp/settings.jsonc`<br>instructions: `AGENTS.md`<br>plugins: `.amp/plugins/**`<br>skills: `.amp/skills/**`<br>commit: `(?i)co-authored-by:\s*amp\s*<amp@ampcode\.com>`, `(?i)<amp@ampcode\.com>`, `(?i)^\s*amp-thread:\s*https://` |
| Claude Code | Anthropic | `cli-agent` | env: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_*`, `CLAUDECODE`, `CLAUDE_PLUGIN_ROOT`<br>agents: `.claude/agents/**`<br>commands: `.claude/commands/**`<br>config: `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`<br>hooks: `.claude/hooks/**`<br>ignore: `.claudeignore`<br>instructions: `CLAUDE.md`, `AGENTS.md`, `.claude/CLAUDE.md`<br>marketplace: `.claude-plugin/marketplace.json`, `**/.claude-plugin/plugin.json`<br>memory: `.claude/**/memory/**`, `.vulnetix/memory.yaml`<br>plugins: `.claude/plugins/**`<br>skills: `.claude/skills/**`, `skills-lock.json`<br>commit: `(?i)co-authored-by:\s*claude\b`, `(?i)^\s*claude-session:\s*https://claude\.ai`, `(?i)generated with \[?claude code`, `(?i)<noreply@anthropic\.com>` |
| Codebuff | Codebuff | `cli-agent` | env: `CODEBUFF_*`<br>config: `.codebuff/**`, `codebuff.json`<br>ignore: `.codebuffignore`<br>instructions: `AGENTS.md`<br>skills: `.codebuff/skills/**` |
| Command Code | Command | `cli-agent` | config: `.commandcode/**`<br>instructions: `AGENTS.md`<br>skills: `.commandcode/skills/**` |
| Coro Code | Coro | `cli-agent` | env: `CORO_*`<br>config: `.coro/context.json` |
| Cortex Code | Cortex | `cli-agent` | config: `.cortex/**`<br>instructions: `AGENTS.md`<br>skills: `.cortex/skills/**` |
| Crush | Charm | `cli-agent` | config: `.crush/**`, `crush.json`, `.crush.json`<br>instructions: `CRUSH.md`, `AGENTS.md`<br>skills: `.crush/skills/**` |
| Droid | Factory | `cli-agent` | config: `.factory/**`<br>instructions: `AGENTS.md`<br>skills: `.factory/skills/**`<br>commit: `factory-droid\[bot\]`, `(?i)<\d+\+factory-droid\[bot\]@users\.noreply\.github\.com>` |
| Forge | Antinomy (ForgeCode) | `cli-agent` | env: `FORGE_*`<br>agents: `.forge/agents/**`<br>commands: `.forge/commands/**`<br>config: `.forge/**`, `forge.yaml`, `.forge.toml`<br>instructions: `AGENTS.md`<br>skills: `.forge/skills/**` |
| Gemini CLI | Google | `cli-agent` | env: `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENAI_USE_VERTEXAI`<br>config: `.gemini/**`, `.gemini/settings.json`<br>instructions: `GEMINI.md`, `.gemini/GEMINI.md`, `AGENTS.md`<br>skills: `.gemini/skills/**` |
| Goose | Block | `cli-agent` | config: `.goose/**`<br>instructions: `.goosehints`, `AGENTS.md`<br>skills: `.goose/skills/**` |
| Grok CLI | Grok CLI (community) | `cli-agent` | config: `.grok/settings.json` |
| IBM Bob | IBM | `cli-agent` | config: `.bob/**`<br>instructions: `AGENTS.md`<br>skills: `.bob/skills/**` |
| Kimi Code CLI | Moonshot AI | `cli-agent` | env: `KIMI_API_KEY`, `KIMI_CODE_HOME`, `KIMI_MODEL_NAME`<br>instructions: `AGENTS.md`<br>skills: `.kimi/skills/**` |
| Kode | Kode | `cli-agent` | config: `.kode/**`<br>instructions: `AGENTS.md`<br>skills: `.kode/skills/**` |
| Letta Code | Letta | `cli-agent` | env: `LETTA_API_KEY`, `LETTA_BASE_URL`, `LETTA_AGENT_ID`, `LETTA_CONVERSATION_ID`<br>config: `.letta/**`, `.letta/settings.json`<br>ignore: `.letta/.lettaignore`<br>instructions: `AGENTS.md`<br>skills: `.letta/skills/**` |
| MCPJam | MCPJam | `cli-agent` | config: `.mcpjam/**`<br>instructions: `AGENTS.md`<br>skills: `.mcpjam/skills/**` |
| Mistral Vibe | Mistral AI | `cli-agent` | env: `MISTRAL_API_KEY`<br>config: `.vibe/**`<br>instructions: `AGENTS.md`<br>skills: `.vibe/skills/**` |
| Mux | Mux | `cli-agent` | config: `.mux/**`<br>instructions: `AGENTS.md`<br>skills: `.mux/skills/**` |
| Nanocoder | Nano Collective | `cli-agent` | env: `NANOCODER_CONFIG_DIR`, `NANOCODER_CONTEXT_LIMIT`<br>config: `agents.config.json`<br>instructions: `AGENTS.md` |
| Neovate | Neovate | `cli-agent` | config: `.neovate/**`<br>instructions: `AGENTS.md`<br>plugins: `.neovate/plugins/**`<br>skills: `.neovate/skills/**` |
| Octofriend | Synthetic | `cli-agent` | instructions: `OCTO.md` |
| OpenAI Codex | OpenAI | `cli-agent` | env: `OPENAI_API_KEY`, `CODEX_*`<br>config: `.codex/**`, `.codex/config.toml`<br>instructions: `AGENTS.md`, `.codex/AGENTS.md`<br>skills: `.codex/skills/**`<br>commit: `(?i)co-authored-by:\s*codex\s*<(?:noreply|codex)@openai\.com>`, `(?i)<(?:noreply|codex)@openai\.com>`, `chatgpt-codex-connector\[bot\]` |
| OpenClaw | OpenClaw | `cli-agent` | config: `.openclaw/**`<br>instructions: `AGENTS.md`<br>skills: `.openclaw/skills/**` |
| OpenHands | All Hands AI | `cli-agent` | config: `.openhands/**`<br>instructions: `.openhands/microagents/**`, `AGENTS.md`<br>skills: `.openhands/skills/**`<br>commit: `(?i)<openhands@all-hands\.dev>`, `openhands-ai\[bot\]` |
| Pi | Pi | `cli-agent` | config: `.pi/**`<br>instructions: `AGENTS.md`<br>plugins: `.pi/extensions/**`<br>skills: `.pi/skills/**` |
| Plandex | Plandex | `cli-agent` | env: `PLANDEX_*`<br>config: `.plandex-v2/**`, `.plandex-dev-v2/**`<br>ignore: `.plandexignore`<br>commit: `(?m)^\s*\xf0\x9f\xa4\x96 Plandex \xe2\x86\x92\s` |
| Qwen Code | Alibaba | `cli-agent` | env: `DASHSCOPE_API_KEY`<br>config: `.qwen/**`<br>instructions: `QWEN.md`, `AGENTS.md`<br>skills: `.qwen/skills/**` |
| Refact.ai | Small Magellanic Cloud AI | `cli-agent` | config: `.refact/**`<br>commit: `(?i)co-authored-by:\s*refact\s+agent\s*<agent@refact\.ai>`, `(?i)<agent@refact\.ai>` |
| Sketch | Bold Software | `cli-agent` | commit: `(?i)co-authored-by:\s*sketch\s*<hello@sketch\.dev>`, `(?im)^\s*change-id:\s*s[0-9a-f]{16}k\b` |
| VT Code | vinhnx | `cli-agent` | env: `VTCODE_*`<br>agents: `.vtcode/agents/**`<br>config: `vtcode.toml`, `.vtcode/**`<br>instructions: `AGENTS.md`<br>skills: `.vtcode/skills/**` |
| Warp | Warp.dev | `cli-agent` | env: `WARP_HONOR_PS1`, `WARP_IS_LOCAL_SHELL_SESSION`, `WARP_USE_SSH_WRAPPER`<br>ignore: `.warpindexingignore`<br>instructions: `WARP.md`, `**/WARP.md`<br>commit: `(?i)co-authored-by:\s*oz(?:\s+agent)?\s*<oz-agent@warp\.dev>`, `(?i)<(?:oz-)?agent@warp\.dev>` |
| g3 | dhanji | `cli-agent` | env: `G3_*`<br>memory: `.g3/sessions/**`<br>skills: `.g3/skills/**` |
| gptme | gptme | `cli-agent` | env: `GPTME_*`<br>config: `gptme.toml`, `gptme.local.toml`<br>instructions: `AGENTS.md`<br>skills: `.gptme/skills/**` |
| iFlow CLI | iFlow | `cli-agent` | config: `.iflow/**`<br>instructions: `IFLOW.md`, `AGENTS.md`<br>skills: `.iflow/skills/**` |
| opencode | SST | `cli-agent` | env: `OPENCODE_*`<br>agents: `.opencode/agent/**`<br>commands: `.opencode/command/**`<br>config: `.opencode/**`, `opencode.json`, `opencode.jsonc`, `.opencode.json`<br>instructions: `AGENTS.md`, `.opencode/AGENTS.md`<br>skills: `.opencode/skills/**` |
| Bolt | StackBlitz | `cloud-agent` | config: `.bolt/**`, `.bolt/config.json`<br>ignore: `.bolt/ignore`<br>instructions: `.bolt/prompt` |
| Charlie | Charlie Labs | `cloud-agent` | commit: `charliecreates\[bot\]`, `(?i)<198680274\+charliecreates\[bot\]@users\.noreply\.github\.com>`, `(?i)co-authored-by:\s*charliehelps\s*<charlie@charlielabs\.ai>`, `(?i)<charlie@charlielabs\.ai>` |
| Claude GitHub App | Anthropic | `cloud-agent` | commit: `(?i)<209825114\+claude\[bot\]@users\.noreply\.github\.com>` |
| Codegen | Codegen | `cloud-agent` | commit: `codegen-sh\[bot\]`, `(?i)<131295404\+codegen-sh\[bot\]@users\.noreply\.github\.com>` |
| Cosine Genie | Cosine | `cloud-agent` | env: `COSINE_*`<br>config: `.cosine/**`, `cosine.toml`, `.cosine.toml`<br>commit: `(?i)co-authored-by:\s*(?:cosine|genie)\s*<(?:agent|genie)@cosine\.sh>`, `(?i)<(?:agent|genie)@cosine\.sh>` |
| Devin | Cognition | `cloud-agent` | commit: `devin-ai-integration\[bot\]`, `(?i)<158243242\+devin-ai-integration\[bot\]@users\.noreply\.github\.com>`, `(?i)co-authored-by:\s*devin ai\b` |
| Jules | Google | `cloud-agent` | commit: `google-labs-jules\[bot\]`, `(?i)<161369871\+google-labs-jules\[bot\]@users\.noreply\.github\.com>` |
| Lovable | Lovable | `cloud-agent` | config: `.lovable/**`<br>commit: `(?im)^\s*x-lovable-edit-id:\s*edt-[0-9a-f-]+`, `(?i)<159125892\+gpt-engineer-app\[bot\]@users\.noreply\.github\.com>` |
| Ona (Gitpod) | Gitpod | `cloud-agent` | config: `.ona/**`, `.ona/automations.yaml`<br>commit: `(?i)co-authored-by:\s*ona\s*<no-reply@ona\.com>`, `(?i)<no-reply@ona\.com>` |
| OpenAI Codex Cloud | OpenAI | `cloud-agent` | commit: `(?i)<199175422\+chatgpt-codex-connector\[bot\]@users\.noreply\.github\.com>` |
| Replit Agent | Replit | `cloud-agent` | memory: `replit.md`<br>commit: `(?i)<no-reply@replit\.com>`, `(?im)^author:?\s*replit\s+(?:ai\s+)?agent\b`, `(?im)^author:?\s*replit\s+assistant\b` |
| SWE-agent | Princeton NLP | `cloud-agent` | commit: `(?i)<noemail@swe-agent\.com>` |
| Solver | Laredo Labs | `cloud-agent` | env: `SOLVER_*`<br>commit: `(?i)<152345546\+solver-app\[bot\]@users\.noreply\.github\.com>` |
| Tembo | Tembo | `cloud-agent` | commit: `tembo\[bot\]`, `tembo-io\[bot\]`, `(?i)<208362400\+tembo(?:-io)?\[bot\]@users\.noreply\.github\.com>` |
| Tusk | Tusk | `cloud-agent` | config: `.github/workflows/tusk-sanity-check.yml`<br>commit: `(?i)<[0-9]+\+use-tusk\[bot\]@users\.noreply\.github\.com>`, `(?i)co-authored-by:\s*use-tusk\[bot\]\b` |
| v0 | Vercel | `cloud-agent` | env: `V0_API_KEY`<br>commit: `(?i)<it\+v0agent@vercel\.com>`, `(?i)<v0\[bot\]@users\.noreply\.github\.com>` |
| AGENTS.md instructions | agents.md (community) | `convention` | instructions: `**/AGENTS.md`, `**/AGENT.md`, `.rules` |
| Model Context Protocol | Anthropic | `convention` | config: `**/mcp.json`, `.mcp.json`, `**/.mcp.json` |
| Conductor | Conductor | `ide` | env: `CONDUCTOR_*`<br>config: `.conductor/settings.toml`, `.conductor/**`<br>instructions: `.worktreeinclude` |
| Cursor | Anysphere | `ide` | env: `CURSOR_*`<br>commands: `.cursor/commands/**`<br>config: `.cursor/**`, `.cursor/mcp.json`<br>hooks: `.cursor/hooks.json`<br>ignore: `.cursorignore`, `.cursorindexingignore`<br>instructions: `.cursorrules`, `.cursor/rules/**`, `AGENTS.md`<br>skills: `.cursor/skills/**`<br>commit: `(?i)co-authored-by:\s*cursor(?:\s+agent)?\b`, `(?i)<cursoragent@cursor\.com>` |
| Google Antigravity | Google | `ide` | commands: `.agents/workflows/**`, `.agent/workflows/**`<br>instructions: `.agents/rules/**`, `.agent/rules/**`<br>skills: `.agents/skills/**` |
| Kiro | Amazon | `ide` | config: `.kiro/**`<br>hooks: `.kiro/hooks/**`<br>instructions: `.kiro/specs/**`, `AGENTS.md`<br>skills: `.kiro/skills/**`<br>steering: `.kiro/steering/**` |
| Qoder | Alibaba | `ide` | config: `.qoder/**`<br>ignore: `.qoderignore`<br>instructions: `AGENTS.md`, `.qoder/rules/**`<br>memory: `.qoder/repowiki/**`<br>skills: `.qoder/skills/**` |
| Trae | ByteDance | `ide` | config: `.trae/**`<br>instructions: `.trae/rules/**`, `AGENTS.md`<br>skills: `.trae/skills/**` |
| Trae CN | ByteDance | `ide` | config: `.trae/**`<br>instructions: `.trae/rules/**`, `AGENTS.md`<br>skills: `.trae/skills/**` |
| Windsurf | Codeium | `ide` | commands: `.windsurf/workflows/**`<br>config: `.windsurf/**`<br>hooks: `.windsurf/hooks.json`<br>ignore: `.codeiumignore`<br>instructions: `.windsurfrules`, `.windsurf/rules/**`, `AGENTS.md`<br>skills: `.windsurf/skills/**` |
| Zed | Zed Industries | `ide` | config: `.zed/**`, `.zed/settings.json`<br>instructions: `.rules`, `AGENT.md`, `AGENTS.md`<br>skills: `.zed/skills/**` |
| Amazon Q Developer | Amazon | `ide-extension` | env: `AMAZON_Q_*`<br>config: `.amazonq/**`<br>instructions: `.amazonq/rules/**`, `AGENTS.md`<br>skills: `.amazonq/skills/**`<br>commit: `amazon-q-developer\[bot\]` |
| Augment | Augment Code | `ide-extension` | config: `.augment/**`<br>ignore: `.augmentignore`<br>instructions: `.augment-guidelines`, `.augment/rules/**`, `AGENTS.md`<br>skills: `.augment/skills/**` |
| Bito | Bito | `ide-extension` | config: `.bito.yaml`, `.bito.yml` |
| Cline | Cline | `ide-extension` | config: `.cline/**`<br>hooks: `.clinerules/hooks/**`<br>instructions: `.clinerules`, `.clinerules/**`, `AGENTS.md`<br>skills: `.cline/skills/**` |
| CodeBuddy | Tencent | `ide-extension` | config: `.codebuddy/**`<br>instructions: `AGENTS.md`<br>skills: `.codebuddy/skills/**` |
| Continue | Continue | `ide-extension` | env: `CONTINUE_*`<br>config: `.continue/**`, `.continue/config.json`, `.continue/config.yaml`, `.continuerc.json`<br>ignore: `.continueignore`<br>instructions: `.continue/rules/**`, `AGENTS.md`<br>skills: `.continue/skills/**` |
| GitHub Copilot | GitHub | `ide-extension` | env: `GITHUB_COPILOT_*`, `COPILOT_*`<br>config: `.copilot/**`, `.vscode/mcp.json`<br>instructions: `.github/copilot-instructions.md`, `.github/instructions/**`, `AGENTS.md`<br>prompts: `.github/prompts/**`<br>skills: `.copilot/skills/**`<br>commit: `(?i)co-authored-by:\s*copilot\s*<copilot@github\.com>`, `(?i)<copilot@github\.com>`, `copilot-swe-agent\[bot\]`, `(?i)<\d+\+copilot@users\.noreply\.github\.com>` |
| JetBrains AI Assistant | JetBrains | `ide-extension` | config: `.aiassistant/**`<br>instructions: `.aiassistant/rules/**`, `AGENTS.md` |
| Junie | JetBrains | `ide-extension` | config: `.junie/**`<br>instructions: `.junie/guidelines.md`, `AGENTS.md`<br>skills: `.junie/skills/**` |
| Kilo Code | Kilo | `ide-extension` | config: `.kilocode/**`, `.kilocodemodes`<br>instructions: `.kilocode/rules/**`, `AGENTS.md`<br>skills: `.kilocode/skills/**` |
| Pochi | Pochi | `ide-extension` | config: `.pochi/**`<br>instructions: `AGENTS.md`<br>skills: `.pochi/skills/**` |
| Qodo | Qodo | `ide-extension` | config: `.codiumai.toml`, `.ai_config.toml` |
| Roo Code | Roo | `ide-extension` | config: `.roo/**`, `.roomodes`<br>instructions: `.roorules`, `.roo/rules/**`, `AGENTS.md`<br>skills: `.roo/skills/**` |
| Sourcegraph Cody | Sourcegraph | `ide-extension` | env: `SRC_ACCESS_TOKEN`<br>config: `.cody/**`, `.sourcegraph/**`, `cody.json`<br>instructions: `.sourcegraph/**/*.rule.md`, `AGENTS.md`<br>skills: `.cody/skills/**` |
| Sourcery | Sourcery | `ide-extension` | config: `.sourcery.yaml` |
| Supermaven | Supermaven | `ide-extension` | ignore: `.supermavenignore` |
| Tabby | TabbyML | `ide-extension` | ignore: `.tabbyignore` |
| Tabnine | Tabnine | `ide-extension` | config: `.tabnine/**`, `.tabnine_root`<br>skills: `.tabnine/skills/**` |
| Tongyi Lingma | Alibaba | `ide-extension` | config: `.lingma/**`<br>ignore: `.tongyiignore`<br>instructions: `.lingma/rules/**`, `AGENTS.md` |
| Traycer | Traycer | `ide-extension` | env: `TRAYCER_*`<br>agents: `.traycer/cli-agents/**`<br>config: `.traycer/**` |
| Zencoder | Zencoder | `ide-extension` | config: `.zencoder/**`<br>instructions: `AGENTS.md`<br>skills: `.zencoder/skills/**` |
| AI21 Labs | AI21 Labs | `service` | env: `AI21_API_KEY` |
| AWS Bedrock | Amazon | `service` | env: `AWS_BEARER_TOKEN_BEDROCK`, `BEDROCK_*` |
| Aleph Alpha | Aleph Alpha | `service` | env: `AA_TOKEN`, `ALEPH_ALPHA_API_KEY` |
| Alibaba DashScope (Qwen) | Alibaba | `service` | env: `DASHSCOPE_API_KEY` |
| Anthropic API | Anthropic | `service` | env: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL` |
| AssemblyAI | AssemblyAI | `service` | env: `ASSEMBLYAI_API_KEY` |
| Azure OpenAI | Microsoft | `service` | env: `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_*` |
| Baichuan | Baichuan Intelligence | `service` | env: `BAICHUAN_API_KEY` |
| Baseten | Baseten | `service` | env: `BASETEN_API_KEY` |
| Black Forest Labs (FLUX) | Black Forest Labs | `service` | env: `BFL_API_KEY` |
| Braintrust | Braintrust | `service` | env: `BRAINTRUST_API_KEY` |
| Cerebras Inference | Cerebras | `service` | env: `CEREBRAS_API_KEY` |
| CodeRabbit | CodeRabbit | `service` | config: `.coderabbit.yaml`, `.coderabbit.yml`<br>commit: `coderabbitai\[bot\]`, `(?i)<coderabbitai@users\.noreply\.github\.com>` |
| Cohere API | Cohere | `service` | env: `COHERE_API_KEY`, `CO_API_KEY` |
| Cubic | Cubic | `service` | commit: `(?i)<[0-9]+\+cubic-dev-ai\[bot\]@users\.noreply\.github\.com>` |
| DeepInfra | DeepInfra | `service` | env: `DEEPINFRA_API_KEY`, `DEEPINFRA_API_TOKEN` |
| DeepSeek API | DeepSeek | `service` | env: `DEEPSEEK_API_KEY` |
| Deepgram | Deepgram | `service` | env: `DEEPGRAM_API_KEY`, `DEEPGRAM_TOKEN` |
| Devlo | Devlo | `service` | commit: `(?i)<[0-9]+\+devloai\[bot\]@users\.noreply\.github\.com>` |
| ElevenLabs | ElevenLabs | `service` | env: `ELEVENLABS_API_KEY` |
| Ellipsis | Ellipsis | `service` | config: `ellipsis.yaml`, `ellipsis.yml`<br>commit: `ellipsis-dev\[bot\]`, `(?i)<65095814\+ellipsis-dev\[bot\]@users\.noreply\.github\.com>` |
| Exa | Exa | `service` | env: `EXA_API_KEY` |
| Fal.ai | Fal | `service` | env: `FAL_KEY`, `FAL_API_KEY` |
| Featherless AI | Featherless AI | `service` | env: `FEATHERLESS_API_KEY`, `FEATHERLESS_AI_API_KEY` |
| Fireworks AI | Fireworks AI | `service` | env: `FIREWORKS_API_KEY` |
| FriendliAI | FriendliAI | `service` | env: `FRIENDLI_TOKEN` |
| Google AI / Vertex | Google | `service` | env: `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENAI_USE_VERTEXAI`, `GOOGLE_CLOUD_PROJECT` |
| Greptile | Greptile | `service` | config: `greptile.json`, `.greptile/**`<br>commit: `(?i)<[0-9]+\+greptile-apps\[bot\]@users\.noreply\.github\.com>` |
| Groq API | Groq | `service` | env: `GROQ_API_KEY` |
| Helicone | Helicone | `service` | env: `HELICONE_API_KEY` |
| Hugging Face | Hugging Face | `service` | env: `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN`, `HUGGINGFACEHUB_API_TOKEN` |
| Hyperbolic | Hyperbolic | `service` | env: `HYPERBOLIC_API_KEY` |
| IBM watsonx.ai | IBM | `service` | env: `WATSONX_APIKEY`, `WATSONX_URL`, `WATSONX_PROJECT_ID` |
| Inception Labs (Mercury) | Inception Labs | `service` | env: `MERCURY_API_KEY`, `INCEPTION_API_KEY` |
| Jina AI | Jina AI | `service` | env: `JINA_API_KEY`, `JINA_AUTH_TOKEN` |
| Korbit | Korbit | `service` | ignore: `.korbitignore`<br>commit: `(?i)<[0-9]+\+korbit-ai\[bot\]@users\.noreply\.github\.com>` |
| Lambda Inference API | Lambda | `service` | env: `LAMBDA_API_KEY` |
| LangSmith | LangChain | `service` | env: `LANGSMITH_API_KEY`, `LANGCHAIN_API_KEY`, `LANGSMITH_ENDPOINT`, `LANGCHAIN_TRACING_V2` |
| Langfuse | Langfuse | `service` | env: `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, `LANGFUSE_HOST` |
| Lepton AI | Lepton AI | `service` | env: `LEPTON_API_TOKEN` |
| Luma AI | Luma AI | `service` | env: `LUMA_API_KEY` |
| MiniMax | MiniMax | `service` | env: `MINIMAX_API_KEY`, `MINIMAX_GROUP_ID` |
| Mistral API | Mistral AI | `service` | env: `MISTRAL_API_KEY` |
| Mistral Codestral | Mistral AI | `service` | env: `CODESTRAL_API_KEY` |
| Moonshot AI (Kimi) | Moonshot AI | `service` | env: `MOONSHOT_API_KEY` |
| NVIDIA NIM / build.nvidia.com | NVIDIA | `service` | env: `NVIDIA_API_KEY`, `NVIDIA_NIM_API_KEY` |
| Nebius AI Studio | Nebius | `service` | env: `NEBIUS_API_KEY` |
| Novita AI | Novita AI | `service` | env: `NOVITA_API_KEY` |
| Ollama | Ollama | `service` | env: `OLLAMA_HOST`, `OLLAMA_MODELS` |
| OpenAI API | OpenAI | `service` | env: `OPENAI_API_KEY`, `OPENAI_ORG_ID`, `OPENAI_ORGANIZATION`, `OPENAI_BASE_URL`, `OPENAI_API_BASE` |
| OpenRouter | OpenRouter | `service` | env: `OPENROUTER_API_KEY` |
| Perplexity API | Perplexity | `service` | env: `PERPLEXITY_API_KEY`, `PPLX_API_KEY` |
| Portkey | Portkey | `service` | env: `PORTKEY_API_KEY` |
| Predibase | Predibase | `service` | env: `PREDIBASE_API_TOKEN`, `PREDIBASE_TENANT_ID` |
| Qodo Merge (PR-Agent) | Qodo | `service` | config: `.pr_agent.toml`<br>commit: `(?i)<[0-9]+\+qodo-merge\[bot\]@users\.noreply\.github\.com>` |
| Reka AI | Reka AI | `service` | env: `REKA_API_KEY` |
| Replicate | Replicate | `service` | env: `REPLICATE_API_TOKEN` |
| Runway | Runway | `service` | env: `RUNWAY_API_KEY`, `RUNWAYML_API_SECRET` |
| SambaNova Cloud | SambaNova | `service` | env: `SAMBANOVA_API_KEY` |
| Sarvam AI | Sarvam AI | `service` | env: `SARVAM_API_KEY` |
| Serper | Serper | `service` | env: `SERPER_API_KEY` |
| Stability AI | Stability AI | `service` | env: `STABILITY_API_KEY` |
| StepFun | StepFun | `service` | env: `STEPFUN_API_KEY`, `STEP_API_KEY` |
| Sweep | Sweep | `service` | config: `sweep.yaml`<br>commit: `(?i)<sweep@sweep\.dev>`, `(?i)<\d+\+sweep-nightly\[bot\]@users\.noreply\.github\.com>`, `sweep-nightly\[bot\]` |
| Tavily | Tavily | `service` | env: `TAVILY_API_KEY` |
| Together AI | Together | `service` | env: `TOGETHER_API_KEY`, `TOGETHER_AI_API_KEY` |
| Upstage (Solar) | Upstage | `service` | env: `UPSTAGE_API_KEY` |
| Vercel AI Gateway | Vercel | `service` | env: `AI_GATEWAY_API_KEY` |
| Volcengine Ark (Doubao) | ByteDance | `service` | env: `ARK_API_KEY`, `VOLCENGINE_API_KEY` |
| Voyage AI | Voyage AI | `service` | env: `VOYAGE_API_KEY` |
| Writer | Writer | `service` | env: `WRITER_API_KEY` |
| Zhipu AI / BigModel (GLM) | Zhipu AI | `service` | env: `ZHIPUAI_API_KEY`, `ZHIPU_API_KEY`, `BIGMODEL_API_KEY` |
| xAI API | xAI | `service` | env: `XAI_API_KEY`, `GROK_API_KEY` |
