# Vulnetix runtime sensor

`vulnetix-sensor` runs in your workload and applies your organisation's virtual
patches and countermeasures from its published detection rule feeds. It reports
every match to the console's Sensors page (`/resolve/sensor`), where you
decide about anything it holds.

## Modes

| Mode | What it does |
|---|---|
| `monitor` | Reports every match. Blocks nothing. |
| `guard` | Holds a match on a rule safe to block (the request gets a 403 saying it is held for review) until you confirm a block, mark a false positive or allow it once. An unanswered hold lapses to allow, and that subject is not held again. |
| `enforce` | Blocks matches on rules that start in block mode. |

In every mode:

- A rule from a feed the sensor cannot verify against `--feed-key` reports and never blocks.
- An indicator list the site serves (a `catalog:` or `org:` feed) reports and never blocks.
- A rule whose start mode is `log` reports and never blocks.
- A request on a `--health-path` is never held.
- A rule that holds more than 20 distinct requests in five minutes trips a breaker and reports only, until you decide about it.

## What it runs

| Rule format | Engine |
|---|---|
| ModSecurity | Coraza, in front of your app (`--listen`, `--upstream`) |
| Layer 7 regex | Go RE2; a pattern that needs lookaround or backreferences is rejected, not approximated |
| STIX, OpenIOC | Domain, address and hash sets; outbound calls through `--egress-listen` are checked against them |
| Sigma, `process_creation` | Evaluated against each process start from Tetragon (`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `CurrentDirectory`, `User`). A rule for another logsource, or with an unsupported field, modifier or aggregation, is rejected with the reason |
| YARA | A pure-Go evaluator over the binary of each process start (64 MB cap): text strings (nocase, wide, ascii, fullword), hex strings with wildcards, jumps and alternation, regexes, and conditions with and/or/not, `N of`, `filesize` and `uintN(offset)`. Modules, for loops, counts, offsets, `at`/`in`, xor and base64 are rejected with the reason |
| Snort, Suricata, AWS WAF, Cloudflare, nginx | Not run by this sensor; reported as `no-engine` |

Every rule's load result is reported, so the console only calls a rule protecting
where a sensor compiled it and runs it in block mode.

With `--tetragon-export`, the sensor reads process starts from
[Tetragon](https://tetragon.io), which does the kernel side with eBPF. It hashes
each new executable and reports any whose hash is an indicator in your feeds.
This detects and reports; it does not stop the process, and the sensor reports
`ebpf` on and `bpfLsm` off so the console says it cannot block there.

To refuse those execs in the kernel, render a Tetragon policy from your feeds
and apply it yourself:

```sh
vulnetix-sensor tetragon-policy --feed <url> > vulnetix-exec-block.yaml
kubectl apply -f vulnetix-exec-block.yaml
```

Only Sigma rules in block mode whose one selection tests `Image` (exact,
`startswith` or `endswith`) can be expressed; the rest are listed on stderr
with the reason and stay detection only. The policy overrides
`security_bprm_creds_for_exec` with `EPERM`, which needs a kernel built with
`CONFIG_BPF_KPROBE_OVERRIDE`. It blocks in every sensor mode and is not updated
by the sensor, so render it again after a rule changes or is marked a false
positive. The sensor reads Tetragon's record of each refusal and reports it as
blocked under the rule that matched. This has not been run against a live
Tetragon yet; read the policy before you apply it.

With `--dns-listen`, the sensor is a DNS forwarder: point the workload's resolver
at it, and a lookup of an indicator domain (or any subdomain of one) answers
NXDOMAIN in enforce, is held in guard, and is reported in monitor. This covers
software that ignores `HTTPS_PROXY`. Lookups it cannot parse are forwarded.

### Refusing execs in the kernel with BPF LSM

With `--bpf-lsm`, the sensor loads its own BPF LSM program on
`bprm_check_security` and refuses an exec of any exact path that a block-mode
Sigma rule names (`Image` with no modifier), from a verified feed. It matches
the file by inode and device, so a renamed or hard-linked copy is refused too.
Monitor reports each match without refusing; guard and enforce refuse with
`EPERM`. A promote, demote or mode change from the console updates the kernel
map at once. The sensor then reports `bpfLsm` on.

It needs root (or `CAP_BPF` with `CAP_SYS_ADMIN`) and a kernel that runs the
bpf LSM: `bpf` must be in `/sys/kernel/security/lsm`, which usually means
adding it to `lsm=` on the kernel command line. Without either, the sensor
logs why and carries on without it.

Limits: a path on an overlay filesystem or a btrfs subvolume can carry a
different device number in the kernel than `stat` reports, so it may not
match; a file replaced on disk is a new inode, covered at the next rule
refresh. The program has been compiled and checked as a spec, but not yet
loaded on a live kernel by its verifier.

### Refusing execs where there is no eBPF (Fargate)

`vulnetix-sensor run` starts the workload itself, under a seccomp filter that
stops every `execve` and `execveat` until the sensor answers. Each exec is
checked with the same Sigma, hash and YARA rules as the Tetragon path, before
it runs, and in guard or enforce a match is refused with `EPERM` (a shell
reports exit 126). Refusing an exec can be undone, so guard holds it like a
request. Every other system call runs untouched.

```sh
vulnetix-sensor run --mode guard --feed <url> -- /app/server
```

Use it as the container's entrypoint, with the sensor binary copied into the
image. It needs no capability beyond what any process has; it sets
`no_new_privs`, so a setuid binary in the workload no longer gains privilege.
It is off unless you start the workload this way, and it reports `seccomp` on.

Limits:

- It covers the workload it started and that workload's children, nothing else
  on the host.
- The path is read from the workload's memory while the exec waits. A workload
  with a second thread could change it between the check and the kernel's read,
  so this is a policy control for software that is not already hostile.
- It has been tested on Linux 7.2 (amd64). Seccomp user notifications need 5.0
  or later; on Fargate platform 1.4 (kernel 5.10) it should work, and has not
  been run there yet.

The sensor does not use ptrace, and reports it as off.

## Forwarding decisions to Guardian

With `--forward siem`, the sensor also sends every DNS lookup the DNS guard
answers and every connection the egress proxy carries or refuses to Guardian,
the Vulnetix SIEM, matched or not. The Sensors page still gets only the
matches; Guardian gets the whole stream, so a detection can look at the clean
traffic around a hit.

```sh
VULNETIX_SIEM_TOKEN=gdn_... vulnetix-sensor --mode guard --feed <url> \
  --dns-listen 127.0.0.1:53 --egress-listen 127.0.0.1:3128 --forward siem
```

Create the token on the console's Sources page as an Events API ingest token.
It belongs to your organisation, and Guardian files every row under it; a row
never names a tenant. The sensor refuses to start with `--forward siem` and no
token, or with neither `--dns-listen` nor `--egress-listen`.

| Setting | Flag | Environment | Default |
|---|---|---|---|
| Ingest token | `--siem-token` | `VULNETIX_SIEM_TOKEN` | none; required |
| Events route | `--siem-url` | `VULNETIX_SIEM_URL` | `https://ingest.vulnetix.com/v1/ingest/events` |

Prefer the environment variable for the token: a flag shows in `ps`.

Each lookup is a `dns_events` row (`qname`, `qtype`, `rcode`, `answers`,
`src_ip`) and each connection a `net_events` row (`src_ip`, `src_port`,
`dst_host`, `dst_ip`, `dst_port`, `proto` tcp, `bytes` in both directions,
`direction` egress), with `host` set to the machine name. `action` is `allow`
or `block`; a hold refuses while it lasts, so it is `block`, and `raw.decision`
keeps the sensor's own word (`allowed`, `held`, `blocked`) with the reason.
`policy` is `<rule table>:<rule uuid>` when a rule matched. A refused
connection is sent at once; one the proxy carried is sent when it closes, so a
long-lived tunnel appears when it ends.

Forwarding never slows a decision. Rows wait in memory (at most 20,000; the
oldest are dropped past that and counted) and go in one request every 10
seconds, or as soon as 1,000 are waiting. A request that fails or takes more
than 10 seconds is dropped, not retried, and the failure is logged at most
once a minute with the running drop count. What is left when the sensor stops
is sent once more on the way out.

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

A running sensor reports the same inventory every `--inventory-every` (default
6h) from `--host-root`, so a finding page can say whether the vulnerable
package is loaded, and where.

## Feed references

`--feed` and the profile's `config.feeds` take three forms:

| Reference | What the sensor loads |
|---|---|
| `https://vulnetix.com/feeds/<org>/<feed>` | A signed Vulnetix rule feed, fetched directly and verified against `--feed-key`. The only kind whose rules may hold or block. |
| `catalog:<id>` | A built-in indicator feed, from `<endpoint>/v1/runtime/feeds/catalog/<id>/indicators`. |
| `org:<uuid>` | One of your org's own feeds (a URL feed or a connector stream), from `<endpoint>/v1/runtime/feeds/org/<uuid>/indicators`. |

The site fetches and parses `catalog:` and `org:` feeds and serves each as one
list of domains, addresses, URLs and SHA-256 hashes. The sensor fetches it with
its own credential (the enrolled device's, or the ApiKey), so these need a
credential and are skipped with `--offline`. Each loads as one `IOC_LIST` rule
that reports and never blocks, and is polled with its etag on the feed refresh
(5 minutes), so an unchanged list costs a 304. A list that fails to fetch keeps
the last one it had, and so does every other feed: one feed changing never
drops another's rules. Anything else in the list is logged and skipped.

## The feed signing key

Release builds pin the feed signing public key from the repository variable
`VULNETIX_FEED_PUBLIC_KEY`, so `--feed-key` is only needed to override it
(`VULNETIX_FEED_KEY` does the same, for a rotation). Generate the pair once with
OpenSSL, on a trusted machine:

```sh
umask 077
openssl genpkey -algorithm ed25519 -out feed-signing-key.pem
# vdb-site secret VULNETIX_FEED_SIGNING_KEY: the 32-byte seed, base64
openssl pkey -in feed-signing-key.pem -outform DER | tail -c 32 | base64 -w0
# cli repository variable VULNETIX_FEED_PUBLIC_KEY: the 32-byte public key, base64
openssl pkey -in feed-signing-key.pem -pubout -outform DER | tail -c 32 | base64 -w0
```

Keep the PEM file offline or in your secrets manager, not in a repository.
Republish each feed after the secret is set, so its manifest is signed.

The current key's PEM is in Bitwarden (`signing/VULNETIX_FEED_SIGNING_KEY_PEM`, with the
public key in `signing/VULNETIX_FEED_PUBLIC_KEY_TXT`); its seed is in AWS Secrets Manager
`prod/vdb-site-api/secrets:VULNETIX_FEED_SIGNING_KEY`, which vdb-site reads. No machine keeps
a copy. To rotate it, follow BREAK-GLASS 6.1 in the private Vulnetix/ops repository.

## Enroll with a provisioning profile

On a host (a laptop, a VM, an EC2 instance you manage yourself), enroll the
sensor instead of writing credentials by hand. The org's provisioning profile
decides which credential the host gets and which config it runs, and an edit
to the profile reaches every enrolled host within five minutes, without a
reinstall. API: vdb-site `docs/sensor-provisioning-api.md`.

```sh
# a person, signed in with the CLI
vulnetix auth login --store home
sudo vulnetix-sensor enroll --from-cli-login

# no person: an MDM pushes the integration's private key and runs
sudo vulnetix-sensor enroll --mdm-key /etc/vulnetix/mdm.key --integration <uuid> --kid k1

# or download, verify and enroll in one step
curl -fsSL https://raw.githubusercontent.com/Vulnetix/cli/main/deploy/sensor/install.sh | sudo sh -s -- --enroll --from-cli-login
```

`--from-cli-login` reads `~/.vulnetix/credentials.json` of the user who ran
`sudo`, not root's. The OS keyring is not reachable under `sudo`, so sign in
with `--store home` first. `--api-key` with `--org-id` (or
`VULNETIX_API_KEY` and `VULNETIX_ORG_ID`) enrolls with a personal key instead.
A tenant org key is refused: enrolling names a person.

Enroll writes:

| Path | What |
|---|---|
| `/etc/vulnetix-sensor/credential` | The device credential (`Sensor <deviceUuid>:<secret>`, or an ApiKey for `user-key` and `org-key` profiles), JSON, root only (0600). The service reads it through systemd `LoadCredential=`, so the sensor still runs as a dynamic user. |
| `/etc/vulnetix-sensor/config.json` | The profile and its config. The running sensor writes later pulls to `/var/lib/vulnetix-sensor/config.json`; the newer of the two is used. |
| `/usr/local/bin/vulnetix-sensor` | The binary, copied there if enroll ran from somewhere else. |
| `/etc/systemd/system/vulnetix-sensor.service` | The sensor, `--config-dir /etc/vulnetix-sensor`. `/etc/vulnetix-sensor.env` is still read when present, and credentials in it win over the device credential. |
| `/etc/systemd/system/vulnetix-sensor-guard.{service,timer}` | Runs `vulnetix-sensor guard-check` as root every minute. |
| `/etc/polkit-1/rules.d/50-vulnetix-sensor.rules` | Hardened and locked only. |

The profile's config is the default for every sensor flag; a flag in the
unit's `ExecStart` wins. A change to the mode, hold time or feeds is applied
live. A sensor that long-polls decisions learns of a profile change
from the site at once and pulls it within ten seconds; otherwise within five
minutes. A change to a listener, forwarding or the inventory interval makes the
sensor exit, and systemd starts it on the new config. Once the device is
revoked, the sensor logs `DEVICE REVOKED`, keeps enforcing the rules it has
and reports nothing more. On SIGTERM it tells the console it stopped
(`goodbye`, reason `signal`), so a stop shows as a stop, not as a silent host.

### Protection levels

| Level | What it adds |
|---|---|
| `standard` | The service as `install.sh` writes it. The guard only keeps the units in step with the profile, so raising the level later takes effect without a reinstall. |
| `hardened` | `Type=notify` with `WatchdogSec=30` (the sensor pings at half that). `StartLimitIntervalSec=0`, so it is never given up on. `RefuseManualStop=yes` on the service and the guard timer, unless the profile allows a user stop. A polkit rule refuses anyone but root managing the sensor or its guard. polkit is not told which unit an enable, disable or mask is for, so that rule refuses those to anyone but root for every unit: on a hardened host, an administrator changes unit files with `sudo`. Every minute the guard unmasks, enables and starts a sensor that was masked, disabled or stopped, and reports it (`goodbye`, reason `stop`, "restored by guard"). With `allowUserStop`, a stopped sensor stays stopped. |
| `locked` | Hardened, never allows a user stop, and `uninstall` needs a one-time code from the console. |

Root can always remove the sensor by hand. Protection makes that a deliberate
act that the console sees, not something a user does by accident.

### Managing an enrolled host

```sh
vulnetix-sensor status          # enrolled, profile, protection, etag, service state; exits 3 when not running
vulnetix-sensor config          # the profile config the sensor runs
sudo vulnetix-sensor enroll --print --protection hardened   # preview the units; contacts nothing
sudo vulnetix-sensor uninstall  # --code <code> when the profile is locked
```

`uninstall` tells the site (a locked device's code is checked before anything
stops), sends `goodbye` with reason `uninstall`, then removes the units, the
polkit rule, the credential and the config. The binary and the sensor key in
`/var/lib/vulnetix-sensor` are left. Running `enroll` again on an enrolled
host is safe: the site revokes the old credential and issues a new one for the
same device.

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
| EKS | `kubernetes-sidecar.yaml`: the sensor as a sidecar in the pod; `kubernetes-node-daemonset.yaml`: one per node beside Tetragon, for process starts |
| Lambda | The layer `vulnetix-sensor-lambda-layer-<arch>.zip` from the release (or `lambda/build-layer.sh`), with `AWS_LAMBDA_EXEC_WRAPPER=/opt/vulnetix/wrapper`. See below. |

Build the container image with `deploy/sensor/Dockerfile`; no image is
published yet.

### Lambda

Lambda has no kernel hooks and no port in front of a function, so the sensor
runs as an external extension and sits on the Runtime API. The wrapper points
the runtime at the sensor; when the runtime asks for its next invocation, an
API Gateway (REST or HTTP API) or function URL event is inspected as an HTTP
request first. A blocked or held request is answered with a 403 on the
function's behalf and the handler never runs. Every other event passes through
untouched.

Add the layer, then set on the function:

| Variable | Value |
|---|---|
| `AWS_LAMBDA_EXEC_WRAPPER` | `/opt/vulnetix/wrapper` |
| `VULNETIX_SENSOR_FEEDS` | comma-separated feed URLs |
| `VULNETIX_FEED_KEY` | the feeds' public key |
| `VULNETIX_SENSOR_MODE` | `monitor`, `guard` or `enforce` |
| `VULNETIX_SENSOR_EGRESS` | optional port, e.g. `9010`, to route SDK calls through the egress proxy |
| `VULNETIX_ORG_ID`, `VULNETIX_API_KEY` | credentials, from Secrets Manager through your deployment tool |

In Lambda, guard holds the one invocation (it cannot wait for a person) and
the event still lands in the hold queue for your decision on later ones.

## Flags

```
--mode monitor|guard|enforce   default monitor
--hold 15m                     how long guard holds a match
--listen :8080                 inbound proxy address
--upstream http://127.0.0.1:8081
--health-path /healthz         repeatable; never held
--egress-listen 127.0.0.1:3128 outbound proxy (set HTTPS_PROXY to it)
--dns-listen 127.0.0.1:53      DNS guard (UDP); point the resolver at it
--dns-upstream 10.0.0.2:53     where it forwards (default: /etc/resolv.conf)
--bpf-lsm                      refuse block-mode exact paths in the kernel (root, bpf LSM)
--tetragon-export <file>       Tetragon's JSON export; check every process start
--host-root /                  where the host filesystem is mounted
--feed <ref>                   repeatable; a feed URL, catalog:<id> or org:<uuid>
--feed-key <base64>            Ed25519 public key the feeds are signed with
--state-dir /var/lib/vulnetix-sensor
--endpoint https://www.vulnetix.com/api/site
--offline                      load rules, report nothing
--forward siem                 copy every DNS and egress decision to Guardian
--siem-token gdn_...           Guardian ingest token (default: VULNETIX_SIEM_TOKEN)
--siem-url <url>               Guardian events route (default: VULNETIX_SIEM_URL, else ingest.vulnetix.com)
--config-dir /etc/vulnetix-sensor   an enrolled sensor's credential and profile config
```

Subcommands:

```
enroll       --from-cli-login | --api-key <key> --org-id <org> | --mdm-key <file> --integration <uuid> --kid <id> [--mdm-device-id <id>]
             [--profile <uuid>] [--endpoint <url>] [--no-start] [--print [--protection standard|hardened|locked]]
             [--config-dir <dir>] [--state-dir <dir>]
status       [--config-dir <dir>] [--state-dir <dir>]
config       [--config-dir <dir>] [--state-dir <dir>]
uninstall    [--code <code>] [--config-dir <dir>] [--state-dir <dir>] [--endpoint <url>]
goodbye      --reason signal|stop|uninstall|upgrade [--detail <text>]
guard-check  run by vulnetix-sensor-guard.timer
inventory    [--root /]
run          <sensor flags> -- <command>
tetragon-policy --feed <url> [--feed-key <base64>]
```

API: vdb-site `docs/runtime-sensor-api.md`.
