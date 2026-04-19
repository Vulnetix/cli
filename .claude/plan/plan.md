# Plan: Generate Rego rules from OWASP ASVS

We will implement a pipeline that fetches every markdown file from the OWASP ASVS 5.0/en directory, extracts security requirements, and produces Rego policies covering those requirements.

## Steps
1. **Discover ASVS markdown files** – Use GitHub API to list all *.md files in `5.0/en`.
2. **Create a sub‑agent (`asvs_fetcher`)** that accepts a raw URL, downloads the markdown, parses headings and bullet points into a JSON rule list.
3. **Iterate over every markdown URL**, invoking the sub‑agent and aggregating all rule JSON objects.
4. **Map each rule to a generic Rego template** (hard‑coded secret detection, unsafe function usage, etc.) and generate a `.rego` file per ASVS topic under `internal/sast/builtin/`.
5. **Write the Rego files** with a header comment containing the source URL and rule description.
6. **Update the SAST documentation index** (`website/content/docs/sast-rules/_index.md`) to list the new policies.
7. **Run the test suite** (`just test`) to ensure the build still succeeds.

## Outputs
- Generated Rego files in `internal/sast/builtin/` (e.g., `0x10.rego`).
- Updated `_index.md` linking each policy to its ASVS source.
- JSON summary of all discovered rules stored at `internal/sast/asvs_rules.json` (optional for debugging).