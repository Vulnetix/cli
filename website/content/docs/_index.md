---
title: Documentation
next: /docs/getting-started
---

Welcome to the Vulnetix CLI documentation. Choose a section to get started.

{{< cards >}}
  {{< card link="getting-started" title="Getting Started" subtitle="Install Vulnetix CLI on your platform." icon="download" >}}
  {{< card link="cli-reference" title="CLI Reference" subtitle="Commands, flags, and usage patterns." icon="terminal" >}}
  {{< card link="cli-reference/reachability" title="Reachability Analysis" subtitle="Tree-sitter source-level reachability for every CVE." icon="search-circle" >}}
  {{< card link="ci-cd" title="CI/CD Integrations" subtitle="GitHub Actions, GitLab CI, Bitbucket, Azure DevOps." icon="cog" >}}
  {{< card link="enterprise" title="Enterprise" subtitle="Corporate proxy, publishing, and distribution." icon="globe-alt" >}}
  {{< card link="sast-rules" title="SAST Rules" subtitle="Built-in static analysis rules with remediation guides." icon="shield-check" >}}
{{< /cards >}}

## What's new

- **Tree-sitter reachability** — Every `vulnetix vdb vuln` lookup now runs CVE-specific tree-sitter queries against your project, reporting exact `file:line:line` matches for the vulnerable pattern. Direct mode confirms the pattern is in the installed package; transitive mode finds first-party callers. 17 languages bundled. See [Reachability Analysis](cli-reference/reachability/).
- **VDB API v2 is the default** — Previous releases defaulted to `-V v1`; current releases default to **v2**. The v2 surface adds timelines, scorecards, KEV merging, parallel fixes, and the tree-sitter queries powering reachability. Pass `-V v1` only when explicitly required; v1 will be removed in a future release.
