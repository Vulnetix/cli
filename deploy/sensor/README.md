# Vulnetix runtime sensor

`vulnetix-sensor` runs in your workload and applies your organisation's virtual
patches and countermeasures from its published detection rule feeds. It reports
every match to the console's Runtime page (`/resolve/runtime`), where you
decide about anything it holds.

## Modes

| Mode | What it does |
|---|---|
| `monitor` | Reports every match. Blocks nothing. |
| `guard` | Holds a match on a rule safe to block (the request gets a 403 saying it is held for review) until you confirm a block, mark a false positive or allow it once. An unanswered hold lapses to allow, and that subject is not held again. |
| `enforce` | Blocks matches on rules that start in block mode. |

In every mode:

- A rule from a feed the sensor cannot verify against `--feed-key` reports and never blocks.
- A rule whose start mode is `log` reports and never blocks.
- A request on a `--health-path` is never held.
- A rule that holds more than 20 distinct requests in five minutes trips a breaker and reports only, until you decide about it.

## What it runs

| Rule format | Engine |
|---|---|
| ModSecurity | Coraza, in front of your app (`--listen`, `--upstream`) |
| Layer 7 regex | Go RE2; a pattern that needs lookaround or backreferences is rejected, not approximated |
| STIX, OpenIOC | Domain, address and hash sets; outbound calls through `--egress-listen` are checked against them |
| Snort, Suricata, YARA, Sigma, AWS WAF, Cloudflare, nginx | Not run by this sensor; reported as `no-engine` |

Every rule's load result is reported, so the console only calls a rule protecting
where a sensor compiled it and runs it in block mode.

The sensor does not yet use eBPF, ptrace or DNS interception. Process and file
events are not watched, and outbound calls from software that ignores
`HTTPS_PROXY` are not checked. It reports those capabilities as off, so the
console says so too.

## Which packages are in use

`vulnetix-sensor inventory` reads `/proc/*/maps` and the package databases and
prints, as JSON, every installed package a running process has mapped:

- `loaded`: a live process maps a file the package installed.
- `stale-loaded`: a process maps a file that was replaced or deleted on disk. The
  package on disk may be fixed while the process still runs the old code; restart it.
- `unowned`: executable files mapped by a process that no package installed.
- `memfdExec`: processes running code from an anonymous memory file. Fileless
  malware does this, and so do JIT runtimes and browsers, so treat it as a lead.

Run it as root to read every process; `unreadable` counts the ones it could not.

## Install

The sensor takes the CLI's credentials: `VULNETIX_ORG_ID` and `VULNETIX_API_KEY`
(the HMAC of the org id keyed by the org secret), or the file `vulnetix auth
login` writes. Every release attaches `vulnetix-sensor-linux-amd64` and
`vulnetix-sensor-linux-arm64`, listed in `checksums.txt`.

| Compute | File |
|---|---|
| EC2 | `ssm-document.yaml` (SSM Run Command or a State Manager association), which runs `install.sh` |
| EMR | `install.sh` as a bootstrap action, after writing `/etc/vulnetix-sensor.env` |
| ECS on Fargate or EC2 | `ecs-sidecar.json`: the sensor in front of the app in the same task |
| EKS | `kubernetes-sidecar.yaml`: the sensor as a sidecar in the pod |
| Lambda | Not supported yet. A Lambda extension needs the Runtime API proxy, which this sensor does not have. |

Build the container image with `deploy/sensor/Dockerfile`; no image is
published yet.

## Flags

```
--mode monitor|guard|enforce   default monitor
--hold 15m                     how long guard holds a match
--listen :8080                 inbound proxy address
--upstream http://127.0.0.1:8081
--health-path /healthz         repeatable; never held
--egress-listen 127.0.0.1:3128 outbound proxy (set HTTPS_PROXY to it)
--feed <url>                   repeatable; a published feed's base URL
--feed-key <base64>            Ed25519 public key the feeds are signed with
--state-dir /var/lib/vulnetix-sensor
--endpoint https://www.vulnetix.com/api/site
--offline                      load rules, report nothing
```

API: vdb-site `docs/runtime-sensor-api.md`.
