---
title: "Attest Command Reference"
weight: 12
description: "Verify signatures and in-toto provenance on artefacts, with the Sigstore public-good root built in."
---

The `attest` command verifies signatures and provenance on artefacts you
consume. It reads what [`cdx --sign`](../cdx/) writes — a DSSE envelope and
cosign-compatible detached sidecars — and anything else in those formats.

Run it with no flags:

```bash
vulnetix attest verify sbom.cdx.json
```

```
[OK] sbom.cdx.json is signed, and the signature is valid.

Signed by
  https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
  authenticated by https://token.actions.githubusercontent.com
  certificate issued by Sigstore public-good
  this is the repository you are in

This check is looser than it could be
  any identity this CA will issue to would also pass, not just this one
    vulnetix attest verify sbom.cdx.json --identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main

  any OIDC provider this CA accepts would also pass
    vulnetix attest verify sbom.cdx.json --issuer github
```

## What it checks, and what it does not

Two rules pull against each other, and both matter.

A verifier must not report success for a check it did not run — a green tick over
a skipped chain validation converts an unknown into a false assurance. But a
verifier that answers every question with *"you did not tell me what to trust"*
is not being careful either; it is making you do its job.

So: **do the work by default, and be exact about what was done.**

| Check | Runs by default | Notes |
|-------|-----------------|-------|
| Signature | always | The signature covers the DSSE pre-authentication encoding, not the bare payload |
| Certificate chain | **yes** | Against the built-in Sigstore public-good root |
| Certificate validity | always | An expired keyless certificate **passes**, with the caveat stated — see below |
| Identity | when you pin one | The identity is always *read* and reported regardless |
| Issuer | when you pin one | |
| Transparency log | **no** | Needs the log's public key and an online query — see [below](#the-transparency-log) |

Anything not established becomes a **suggestion** carrying a complete,
pre-filled command. Never a fragment with an ellipsis: a suggestion you have to
complete is one you can only use if you already knew the answer.

### Expired certificates

A Fulcio certificate lives about ten minutes. Failing every signature older than
that would make the verifier useless — the signature was valid when it was made.
So an expired certificate passes, and the detail says what that does and does not
mean: only a transparency-log entry proves the signature predates the expiry.

### The transparency log

Rekor inclusion is the one thing genuinely not doable from the material at hand:
the sidecars carry no log entry, so proving inclusion means querying the log by
artefact hash and verifying its signed tree head — a network dependency and a
second trust root.

Rather than a skipped check dressed up as a gap in your run, it is a suggestion
naming the tool that does it, fully populated:

```
cosign verify-blob --certificate-identity https://github.com/acme/repo/... \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle sbom.cdx.json.intoto.jsonl sbom.cdx.json
```

---

## Trust anchor resolution

`--trusted-root` is an **override for a private Sigstore deployment**, not a
prerequisite. The anchor resolves most-specific first:

| Source | Scope |
|--------|-------|
| `--trusted-root` | This run |
| `SIGSTORE_ROOT_FILE` | This shell or CI job |
| `.vulnetix/trusted-root.pem` | This repository |
| Built in | The Sigstore public-good instance |

A team running a private Sigstore commits its root once and nobody types the
flag again:

```bash
cp fulcio-root.pem .vulnetix/trusted-root.pem
git add .vulnetix/trusted-root.pem
```

The output **names whichever link answered**, so "trusted" is never ambiguous:

```
  certificate issued by .vulnetix/trusted-root.pem
```

A chain that does not anchor to the resolved root **fails**, and the failure
names the flag that would fix it:

```
certificate-chain: does not chain to Sigstore public-good
  (x509: certificate signed by unknown authority).
  If this was signed by a private Sigstore instance, pass --trusted-root
  with its root certificate.
```

The built-in root is pinned rather than fetched over TUF. A test fails once it
expires, so a stale pin is loud rather than an unexplained chain error.

---

## Pinning the signer

A valid signature means *somebody Sigstore trusts* made it — which, for GitHub
Actions, is any workflow in any repository. Pinning the identity is what turns
that into an answer.

```bash
# Exact — the safe default. Paste back what the command printed.
vulnetix attest verify sbom.cdx.json \
  --identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main

# Pattern — for deliberately accepting a set
vulnetix attest verify sbom.cdx.json --identity-regex '^https://github\.com/acme/.*'
```

`--identity` is an **exact** comparison; `--identity-regex` is the pattern form.
This is the split cosign uses, and the safe side is the default for a reason:
every keyless subject is a URL, so under regex semantics every `.` is a wildcard
and `https://github.com/acme/repo` would also match `https://githubXcom/acme/repo`.
The identity the command prints pastes back verbatim.

### Issuer shortcuts

```bash
vulnetix attest verify sbom.cdx.json --issuer github
```

| Shortcut | Issuer |
|----------|--------|
| `github` | `https://token.actions.githubusercontent.com` |
| `gitlab` | `https://gitlab.com` |
| `google` | `https://accounts.google.com` |
| `microsoft` | `https://login.microsoftonline.com` |
| `buildkite` | `https://agent.buildkite.com` |
| `codefresh` | `https://oidc.codefresh.io` |

A full URL is still accepted. Nobody remembers
`token.actions.githubusercontent.com`, and a pin nobody can spell is a pin that
does not get applied.

### --strict

One flag instead of learning three. It requires the signer to be pinned, and
fails naming the exact flags to add — values already filled in from the
certificate it just read:

```bash
$ vulnetix attest verify sbom.cdx.json --strict

strict: --strict requires the signer to be pinned; add:
  --identity https://github.com/acme/repo/.github/workflows/release.yml@refs/heads/main
  --issuer https://token.actions.githubusercontent.com
```

### Is it my repository?

Zero configuration. The signer's repository is compared against the local git
remote, and the output says which it is:

```
  this is the repository you are in
```
```
  a different repository from the one you are in
```

*"Signed by github.com/acme/repo"* is not an answer until you know which of those
it is. It is a **note, not a check** — a third-party artefact legitimately comes
from a third party, and failing on that by default would break the case
verification matters most for.

---

## Flags

```bash
vulnetix attest verify <artifact> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--identity` | - | Require this exact signer |
| `--identity-regex` | - | Require the signer to match this pattern |
| `--issuer` | - | Require this OIDC issuer — a URL or a shortcut name |
| `--strict` | `false` | Require the signer to be pinned; fails naming the flags to add |
| `--trusted-root` | resolved | Root certificate of a private Sigstore deployment |
| `--require` | - | Fail when a named check did not run, e.g. `transparency-log` (repeatable) |
| `--envelope` | `<artifact>.intoto.jsonl` | DSSE envelope |
| `--signature` | `<artifact>.sig` | Detached signature |
| `--certificate` | `<artifact>.pem` | Signing certificate |
| `-o, --output` | `pretty` | `pretty`, `json` |
| `--verbose` | `false` | Show every check, including the ones that passed |

`--identity` and `--identity-regex` are mutually exclusive.

Sidecars are discovered beside the artefact using the suffixes
[`cdx --sign`](../cdx/) writes and stock cosign expects, so there is no second
convention to learn.

### Provenance

When the payload is an in-toto statement, its predicate is read and reported —
SLSA v0.2 and v1 both. It is labelled **claimed, not verified**, because it is
what the payload asserts about itself.

The report names which fields are present rather than a SLSA level. A level is a
property of the build platform and its controls, which no consumer can determine
by reading a document that build produced.

---

## In CI

```yaml
- name: Verify the SBOM came from our own release workflow
  run: |
    vulnetix attest verify sbom.cdx.json \
      --identity "https://github.com/${{ github.repository }}/.github/workflows/release.yml@refs/heads/main" \
      --issuer github
```

Or, verifying a document at the point it is consumed:

```bash
vulnetix bom import vendor-sbom.cdx.json --verify-attestation --strict
```

A failed check aborts the import — see [`bom import`](../bom/#verifying-before-trusting).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every check that ran passed |
| `1` | A check failed, or a `--require`d check did not run |
| `2` | Usage error |

## See also

- [`cdx --sign`](../cdx/) — sign a CycloneDX document with this machine's identity
- [`bom import --verify-attestation`](../bom/) — verify at the point of consumption
- [`tea`](../tea/) — publish artefacts and attestations to a transparency log
