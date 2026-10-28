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
--feed <url>                   repeatable; a published feed's base URL
--feed-key <base64>            Ed25519 public key the feeds are signed with
--state-dir /var/lib/vulnetix-sensor
--endpoint https://www.vulnetix.com/api/site
--offline                      load rules, report nothing
```

API: vdb-site `docs/runtime-sensor-api.md`.
