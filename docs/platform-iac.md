# Platform IaC files

How the CLI decides what a Platform IaC document is and where it finds them. Public
documentation lives at [docs.vulnetix.com](https://docs.vulnetix.com/platform-iac/cli/validate/);
this page is the in-repository reference. The code is `internal/platformiac`.

## The rule

A document is Platform IaC if and only if its `apiVersion` is `vulnetix.com/v1` and its `kind`
is one `vulnetix config kinds` lists: a config-schemas kind, or a local kind (below).

| Case | Result |
|---|---|
| A file in `.vulnetix/config` with no `vulnetix.com/v1` content (SARIF, CycloneDX, OpenVEX, memory, credentials) | Skipped; a note is printed only with `-v` |
| A `vulnetix.com/v1` document whose kind is unknown | Error |
| A file that mixes documents with other content | Error |
| A well-known file holding the wrong kind | Error |
| A file named with `-f` that is not a document | Error |
| A folder file that does not parse but contains `vulnetix.com/v1` | Error (a broken document is never skipped) |

## Where documents are found

| Path | Kind |
|---|---|
| `.vulnetix/config/**` (`.yaml`, `.yml`, `.json`) | any |
| `.vulnetix/ai-firewall.yaml` | `AiFirewallPolicy` |
| `.vulnetix/license-policy.yaml` | `LicensePolicy` |
| `.vulnetix/license-exceptions.yaml` | `LicenseExceptions` |

A well-known licence file written before documents carried `apiVersion` and `kind` is read as
its file's kind, so an older repository keeps working.

| Code | Reads |
|---|---|
| `platformiac.Discover` | the folder and, with `IncludeWellKnown`, the well-known files; or only what `-f` names |
| `platformiac.LoadSingleton(root, kind)` | the one document of a singleton kind, from its well-known file or the folder; defining it in both, or twice, is an error |
| `platformiac.Normalize` / `Flatten` | the config form (`metadata.name: default` plus `spec`) and the repository form (fields at the top level) |

Wiring:

- `config validate` reads the folder and the well-known files.
- `config plan` and `config apply` read the folder and, with no `-f`, the well-known files (v4).
  `ai-firewall.yaml` (AiFirewallPolicy) is sent to the engine, so `config apply --prune` adopts it;
  `license-policy.yaml` and `license-exceptions.yaml` are validated here and never sent (see Local
  kinds). A singleton defined both in a well-known file and in the folder under the same name is a
  duplicate and refused.
- Commands that are aliases of the declarative path (engine first; the legacy endpoint stays, with
  a deprecation warning, when the engine refuses the credential): `config set quality-gate`,
  `config set eol-policy`, `config set package-firewall` (policy form), `ai-firewall apply` and
  `ai-firewall export`. These stay imperative or read-only and are not deprecated:
  `config set package-firewall` (mirror form), `config set jail`,
  `config set ai-firewall provider|model|guardrail`, and every `config get`. The declarative path
  is `config plan`, `config apply` and `config export`.
- `ai-firewall apply` reads its policy through `LoadSingleton` (`pkg/aifirewall`
  `ParsePolicyValue`) unless `-f` names a file.
- `license` and `scan --evaluate-licenses` read the licence policy and exceptions through
  `LoadSingleton` (`loadLicenseGovernance`) unless `--policy-file` or `--exceptions-file` names one.

## Local kinds

A kind whose config-schemas schema carries `x-vulnetix.validateOnly` (`LicenseExceptions`,
`LicensePolicy`) is validated here, never sent to the config engine, and reported by `config plan`
with a note (`platformiac.IsLocal`). The schema comes from config-schemas; nothing is embedded in
the CLI. When vdb-site stores the kind the flag is cleared in a config-schemas release and the CLI
sends it with no change.
