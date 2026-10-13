---
title: "Defend Command Reference"
weight: 5
description: "Block rules and detections for a vulnerability that has no fix: read them, save them in the file your tool loads, and record that a control is in place."
---

The `defend` command is for a finding that has no fix. It lists what Vulnetix has
built from the public exploits for that vulnerability, shows each rule's mode,
false-positive risk and coverage limits, saves a rule in the file its tool loads,
and records that a control is in place so the next scan knows.

> Neither kind of rule replaces patching. A virtual patch buys time.

## Two kinds, never mixed

| | Virtual patch (**block**) | Countermeasure (**detect**) |
|---|---|---|
| What it does | Stops the exploit request | Tells you it happened |
| Where it runs | Your WAF, sensor or web server | Your SIEM, EDR or threat platform |
| Formats | Cloudflare WAF, AWS WAF, Snort, Suricata, ModSecurity, nginx, layer 7 regex | Sigma, YARA, STIX 2.1, OpenIOC |
| Starts in | The mode the rule states, often log only | n/a |

They are listed in separate sections and never share a line. Detection is not
prevention, and the output says so.

## Usage

```bash
vulnetix defend <advisory-id> [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Project directory whose last scan and repo are read |
| `--for` | string | - | Save rules: a format (`modsecurity`, `nginx`, `aws-waf`, `cloudflare`, `snort`, `suricata`, `regex`, `sigma`, `yara`, `stix`, `openioc`), comma-separated; `fits` for every format your repo suggests; `all` |
| `-O, --output-dir` | string | `defences` | Directory the rule files are written to |
| `--record` | string | - | Record that a control is in place, in your own words |
| `--until` | string | 90 days | Date the recorded control expires, `YYYY-MM-DD` |
| `--mode` | string | the rule's own | `block` or `log` |
| `--lane` | string | - | `block` or `detect`, when recording without `--for` |
| `--package` | string | from the last scan | Package the control covers |

The display flags (`--view`, `-v`, `--color`, `--ascii`, `--width`) are accepted
too.

## Reading

```bash
vulnetix defend CVE-2025-12345
```

```text
 legacy-xml 3.1.4 · CVE-2025-12345 · no fix

 BLOCK · 2 virtual patches · they stop the request
 ──────────────────────────────────────────────────────────────────
 ModSecurity      confidence HIGH   start in log only   false positives low
                  ▸ fits your repo  docker/modsec/rules.conf:1 · inferred, not verified as deployed
                  coverage  Matches the public proof of concept. Does not match encoded variants.

 DETECT · 1 countermeasure · it tells you it happened
 Detection is not prevention. It does not stop the exploit.
```

Formats your repository suggests are listed first and marked *fits your repo*.
That comes from reading Terraform, CloudFormation, Dockerfiles, compose files,
Kubernetes manifests and nginx or ModSecurity configuration in the project. It is
inference from files: the CLI cannot see what is actually deployed, and says so.

Reading needs no plan. Rule bodies and downloads need **Pro**; without it you see
how many exist and in which formats.

## Saving

```bash
vulnetix defend CVE-2025-12345 --for modsecurity -o defences/
```

The rule is written under the name its tool expects (`ModSecurity` as
`<id>-modsecurity.conf`, Snort as `<id>-local.rules`, and so on). The body is
checked against the SHA-256 the database sends with it; a body that does not
match is never written.

## Recording a control

```bash
vulnetix defend CVE-2025-12345 --for modsecurity \
    --record "ModSecurity, prod-eu ingress" --until 2027-01-10
```

This writes `.vulnetix/controls.json` and an OpenVEX statement to
`.vulnetix/vex-compensating-controls.json`.

- The finding **stays affected and stays counted**. The VEX status is `affected`
  with an action naming the control. A virtual patch never makes a package
  unaffected, so it is never written as `not_affected`.
- The next scan lists it under **PROTECTED** when a blocking rule is recorded, and
  under **MONITORED** when only a detection, or a block rule still in log-only
  mode, is. MONITORED stops nothing.
- A control **expires**. At `--until` (default 90 days) the finding returns to
  *needs action* with the reason, because a compensating control is a loan against
  a patch that has not arrived.
- The CLI **cannot verify the rule is deployed.** The record is your statement,
  and every output says so.

### Gates

| Flag on `scan` | Effect |
|----------------|--------|
| `--fail-on unprotected` | Fails when a finding has no fix and no unexpired recorded control: "no fix and no plan" |
| `--accept-defended` | Lets an unexpired recorded control satisfy the severity, exploit and malware gates for the finding it covers. Off by default, because the CLI cannot confirm the rule is live |

## In `scan` output

`scan` calls the same lookup for every package whose advisories have no fix and
prints one of these under it:

| Line | Meaning |
|------|---------|
| `◆ block …` / `◆ detect …` | Rules exist, with their formats |
| `◆ 2 block rules and 1 detection exist · Pro unlocks the rules` | They exist; rule bodies need Pro |
| `◆ nothing published for this yet` | Asked, and nothing has been built. It does not mean the vulnerability cannot be defended |
| `◆ not indexed: … is not an advisory identifier the database can look up` | The identifier was not shaped like an advisory id, or the database refused it. Any advisory family is accepted and widened through its aliases |
| `◆ not checked (…)` / `◆ lookup failed (…)` | No answer, which is not the same as none |

`--hide defences` skips the lookup.

Pro plans also see a link to each rule in the Vulnetix console (`console` under the rule), which opens the catalogue entry. Below Pro you still see how many rules exist and in which formats.
