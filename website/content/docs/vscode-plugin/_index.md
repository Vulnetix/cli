---
title: "VS Code plugin"
weight: 12
description: "Run the Vulnetix scanning engine in VS Code and compatible editors, with findings attached to the code and dependencies that caused them."
---

Vulnetix for VS Code runs the same scanning engine as the CLI and puts findings
in the editor while you are working. Dependency vulnerabilities, unsafe code,
secrets, container configuration, infrastructure files and licence policy use
the same rules and organisation policy as `vulnetix scan` in CI.

<div class="vx-cta-row">
  <a href="https://open-vsx.org/extension/vulnetix/vulnetix" class="vx-btn-primary" target="_blank" rel="noopener noreferrer">Install from Open VSX</a>
  <a href="https://docs.code.vulnetix.com" class="vx-feature-link" target="_blank" rel="noopener noreferrer">Read the extension docs &rarr;</a>
</div>

## Install the extension

Open the [Vulnetix listing on Open VSX](https://open-vsx.org/extension/vulnetix/vulnetix)
and use your editor's install action. Cursor, Windsurf, VSCodium, code-server,
Gitpod and other VS Code-compatible editors use Open VSX as their extension
registry. VS Code users can download the VSIX from the same listing and choose
**Extensions: Install from VSIX** from the Command Palette.

The extension identifier is `vulnetix.vulnetix`. Editors with an Open
VSX-backed command-line interface can install it directly:

```sh
codium --install-extension vulnetix.vulnetix
```

See the [editor-specific installation guides](https://docs.code.vulnetix.com/docs/editors/)
for remote workspaces, container images and private extension registries.

## How it uses the CLI

The extension looks for a CLI binary configured through `vulnetix.cli.path`,
then checks `PATH`, then checks its managed storage. If no compatible binary is
available, it offers to download one and verifies the release checksum before
execution.

Scanning stays local. Source files are read by the CLI process on your machine
or in the remote workspace that owns the files. Dependency matching sends
package coordinates to the Vulnetix VDB; it does not upload source code.

## Keep editor and CI results aligned

Use the extension during development and the CLI in your pipeline. Both read
the same project configuration and produce the same finding formats, so a rule
that blocks a pull request can be seen before the change leaves the editor.

- [Scan command reference](../cli-reference/scan/)
- [SAST command reference](../cli-reference/sast/)
- [CI/CD integrations](../ci-cd/)
- [Authentication](../authentication/)
