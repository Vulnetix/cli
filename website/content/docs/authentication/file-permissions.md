---
title: "File Permissions & Isolation"
weight: 4
description: "Hardening credential files on Linux, macOS, and Windows, and inside containers with SELinux, AppArmor, and seccomp."
---

Any credential the CLI writes to disk is written mode `0600` inside a directory created mode `0700`. That is the floor, not the ceiling. This page covers verifying it, restoring it, and defending the file against the rest of the system.

## What the CLI Guarantees

| Path | Mode | Enforced |
|------|------|----------|
| `~/.vulnetix/` (and `--store-dir`) | `0700` | On creation |
| `~/.vulnetix/credentials.json` | `0600` | On every write |
| `./.vulnetix/credentials.json` | `0600` | On every write |
| `~/.netrc` / `~/_netrc` | `0600` | On write **and on read** |

netrc is the only file whose permissions are checked at read time. If it is group- or world-accessible, the CLI refuses to use it:

```
/home/you/.netrc permissions are too open; run chmod 600 /home/you/.netrc
```

`credentials.json` is **not** re-checked on read. A `umask` change, a restore from backup, a `cp -r` between machines, or a container bind mount can all widen it silently. Verify it yourself.

---

## Never Commit Credentials

Before creating a project-scoped credential:

```sh
printf '.vulnetix/credentials.json\n' >> .gitignore
printf '.vulnetix/\n'                 >> .dockerignore
```

`.dockerignore` matters as much as `.gitignore`. A `COPY . .` in a Dockerfile bakes the credential into an image layer where `docker history` and any downstream `FROM` will find it. See [VNX-DOCKER-003](/docs/sast-rules/vnx-docker-003/).

If a credential has already been committed, rotating it is the only fix. Rewriting history does not help: assume anything pushed has been cloned. See [Rotation & Revocation](../rotation/).

---

## Linux

### Verify and Restore

```sh
# Verify
stat -c '%a %U:%G %n' ~/.vulnetix ~/.vulnetix/credentials.json ~/.netrc

# Expected
# 700 you:you /home/you/.vulnetix
# 600 you:you /home/you/.vulnetix/credentials.json
# 600 you:you /home/you/.netrc

# Restore
chmod 700 ~/.vulnetix
chmod 600 ~/.vulnetix/credentials.json ~/.netrc
chown "$(id -un):$(id -gn)" ~/.vulnetix/credentials.json
```

Set a restrictive `umask` in the shell that runs the CLI so newly created files are never group-readable:

```sh
umask 077
```

### POSIX ACLs

Default POSIX modes are not always the whole story. An inherited ACL can grant access that `stat` does not show. Check for a trailing `+` on the mode string, and inspect it:

```sh
getfacl ~/.vulnetix/credentials.json

# Strip every extended ACL entry
setfacl -b ~/.vulnetix/credentials.json
```

### Immutable Flag

On ext4/xfs you can prevent even the owner from modifying the file without first clearing the flag. Useful on a build agent where the credential is provisioned once:

```sh
sudo chattr +i ~/.vulnetix/credentials.json   # set
sudo chattr -i ~/.vulnetix/credentials.json   # clear before `vulnetix auth login`
```

`vulnetix auth login` and `vulnetix auth logout` both fail while `+i` is set. That is the point.

### SELinux

On Fedora, RHEL, CentOS Stream, and derivatives, the file should carry the user-home type. A file restored from a tarball or moved out of `/tmp` often carries `user_tmp_t` instead, which confined processes may be denied.

```sh
# Inspect
ls -Z ~/.vulnetix/credentials.json
# unconfined_u:object_r:user_home_t:s0

# Restore the default label from policy
restorecon -Rv ~/.vulnetix

# Pin a label explicitly
semanage fcontext -a -t user_home_t '/home/[^/]+/\.vulnetix(/.*)?'
restorecon -Rv ~/.vulnetix
```

For a container bind mount, SELinux blocks the container's access unless the mount is relabelled. `:Z` relabels privately to that container; `:z` relabels shared across containers. Prefer `:Z`.

```sh
podman run --rm \
  -v "$HOME/.vulnetix:/root/.vulnetix:ro,Z" \
  -v "$PWD:/workspace:Z" -w /workspace \
  ghcr.io/example/ci vulnetix scan
```

Denials show up in the audit log:

```sh
sudo ausearch -m AVC -ts recent | grep vulnetix
```

### AppArmor

On Ubuntu, Debian, and SUSE, confine the CLI so it can read its own credential and nothing else's. A profile at `/etc/apparmor.d/usr.local.bin.vulnetix`:

```
#include <tunables/global>

/usr/local/bin/vulnetix {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  network inet stream,
  network inet6 stream,

  /usr/local/bin/vulnetix           mr,

  # Its own credentials — read only, nothing else under home
  owner @{HOME}/.vulnetix/          r,
  owner @{HOME}/.vulnetix/**        r,
  owner @{HOME}/.netrc              r,

  # The project being scanned
  owner @{HOME}/**                  r,
  owner @{HOME}/**/.vulnetix/       rw,
  owner @{HOME}/**/.vulnetix/**     rw,

  # Deny every other user's secrets outright
  deny /home/*/.ssh/**              rwx,
  deny /home/*/.aws/**              rwx,
  deny /root/**                     rwx,
}
```

Load and test in complain mode first, then enforce:

```sh
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.vulnetix
sudo aa-complain /usr/local/bin/vulnetix   # log-only, nothing blocked
# exercise the CLI, review /var/log/audit/audit.log or `journalctl -k`
sudo aa-enforce /usr/local/bin/vulnetix
```

Writing an AppArmor profile that grants read on `@{HOME}/**` (needed to scan your source tree) means the profile cannot, by itself, stop the CLI reading `~/.ssh`. The explicit `deny` rules above are what close that. Enumerate the paths that matter to you.

{{< callout type="warning" >}}
**seccomp does not protect credential files.** It filters *syscalls*, not paths — a seccomp profile that permits `openat` permits opening any file the DAC/MAC layers allow. Use SELinux or AppArmor for path confinement, and seccomp for reducing kernel attack surface. They solve different problems.
{{< /callout >}}

### seccomp, Used Correctly

A seccomp profile blocks classes of syscall the CLI never needs, limiting what an exploited process can do after it has read your credential. Docker's default profile already blocks most of these. To go further, run with `--security-opt no-new-privileges` so a setuid binary cannot escalate:

```sh
docker run --rm \
  --security-opt no-new-privileges \
  --security-opt seccomp=/etc/docker/seccomp/vulnetix.json \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  -e VULNETIX_API_TOKEN \
  -v "$PWD:/workspace:ro" -w /workspace \
  ghcr.io/example/ci vulnetix scan
```

`--cap-drop ALL`, `--read-only`, and `no-new-privileges` deliver more real credential safety here than the seccomp profile does. `--read-only` also guarantees the CLI cannot persist a credential file at all, forcing the environment-variable path.

---

## macOS

Unix modes apply exactly as on Linux:

```sh
stat -f '%Lp %Su:%Sg %N' ~/.vulnetix/credentials.json
chmod 600 ~/.vulnetix/credentials.json
chmod 700 ~/.vulnetix
```

macOS also carries extended attributes and ACLs that `stat` hides:

```sh
ls -le@ ~/.vulnetix/credentials.json   # ACL entries and xattrs
chmod -N ~/.vulnetix/credentials.json  # remove ACLs
```

### Prefer the Keychain

On macOS there is no reason to keep a plaintext credential file. `--store keyring` puts the secret in your login keychain, which is encrypted at rest, unlocked with your login password, and gated per-application.

```sh
vulnetix auth login --store keyring
```

Inspect and remove entries directly:

```sh
security find-generic-password -s vulnetix -a "apikey:$ORG_ID" -w
security delete-generic-password -s vulnetix -a "apikey:$ORG_ID"
```

Lock the login keychain when you step away, and set it to lock on sleep:

```sh
security set-keychain-settings -l -u -t 900 ~/Library/Keychains/login.keychain-db
```

If the keychain is locked, keychain reads prompt or fail rather than silently returning the secret. That is the desired behaviour.

### Full Disk Access and Time Machine

`~/.vulnetix` is included in Time Machine backups by default. Exclude it if your backup destination is less trusted than the machine:

```sh
sudo tmutil addexclusion ~/.vulnetix
```

---

## Windows

Unix modes are meaningless; the file is protected by an ACL. Verify that only your account and `SYSTEM` have access:

```powershell
icacls "$env:USERPROFILE\.vulnetix\credentials.json"
```

Reset it to owner-only, breaking inheritance from the parent directory:

```powershell
$Path = "$env:USERPROFILE\.vulnetix"

# Disable inheritance, drop inherited ACEs
icacls $Path /inheritance:r

# Grant only the current user and SYSTEM, applied to children
icacls $Path /grant:r "$($env:USERNAME):(OI)(CI)F"
icacls $Path /grant:r "SYSTEM:(OI)(CI)F"

# Verify no Users / Everyone / Authenticated Users entries remain
icacls $Path
```

The netrc file on Windows is `%USERPROFILE%\_netrc`, not `.netrc`. The CLI does not enforce permissions on it — `checkNetrcPermissions` is a no-op on Windows because POSIX mode bits do not apply. **Set the ACL yourself:**

```powershell
icacls "$env:USERPROFILE\_netrc" /inheritance:r
icacls "$env:USERPROFILE\_netrc" /grant:r "$($env:USERNAME):F"
```

### Prefer Credential Manager

`--store keyring` uses Windows Credential Manager, which encrypts the secret with DPAPI under your user profile:

```powershell
vulnetix auth login --store keyring

# Inspect
cmdkey /list | Select-String vulnetix
```

### EFS

On NTFS with a domain profile you can encrypt the directory at rest:

```powershell
cipher /e /s:"$env:USERPROFILE\.vulnetix"
```

---

## Containers

Ordered from best to worst.

### 1. Environment Variable, Read-Only Root

Nothing is persisted. The credential lives only in the process environment.

```sh
docker run --rm --read-only \
  -e VULNETIX_API_TOKEN \
  -v "$PWD:/workspace:ro" -w /workspace \
  ghcr.io/example/ci vulnetix scan
```

`-e VAR` with no value forwards the value from the host shell, so the secret never appears in the command line or in `docker inspect` output as a literal.

### 2. Mounted Secret File, tmpfs

For Docker Compose, Swarm, and Kubernetes, mount the secret as a file and read it into the environment at the last moment.

```yaml
services:
  scan:
    image: ghcr.io/example/ci
    read_only: true
    secrets: [vulnetix_token]
    tmpfs:
      - /tmp:noexec,nosuid,size=64m
    command: >
      sh -c 'VULNETIX_API_TOKEN="$$(cat /run/secrets/vulnetix_token)" vulnetix scan'

secrets:
  vulnetix_token:
    file: ./vulnetix_token.txt
```

`/run/secrets` is a tmpfs; the secret is never written to the container's writable layer.

In Kubernetes, prefer `secretKeyRef` over mounting when the consumer is a single process:

```yaml
        env:
          - name: VULNETIX_API_TOKEN
            valueFrom:
              secretKeyRef:
                name: vulnetix
                key: token
```

### 3. Build-Time Secret Mount

If a credential is genuinely needed during `docker build`, use a BuildKit secret mount. It is never committed to a layer.

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=vulnetix_token \
    VULNETIX_API_TOKEN="$(cat /run/secrets/vulnetix_token)" \
    vulnetix scan --severity high
```

```sh
docker build --secret id=vulnetix_token,src=./token.txt .
```

### 4. Bind-Mounted Host Credential

Acceptable for local development, read-only, with an SELinux label:

```sh
docker run --rm \
  -v "$HOME/.vulnetix:/root/.vulnetix:ro,Z" \
  -v "$PWD:/workspace:Z" -w /workspace \
  ghcr.io/example/ci vulnetix scan
```

The container runs as `root` by default, so `0600` root-owned files inside it are readable by every process in the container. Run as a non-root user:

```sh
docker run --rm --user "$(id -u):$(id -g)" …
```

### Never

- `ENV VULNETIX_API_KEY=…` in a Dockerfile — visible in `docker history` and every derived image.
- `COPY .vulnetix/ /app/.vulnetix/` — bakes the credential into a layer.
- `--build-arg VULNETIX_API_KEY=…` — recorded in image metadata.
- Passing the secret as a literal argv value — visible to every process via `/proc/*/cmdline`.

The last point applies outside containers too. `vulnetix auth login --api-key 6e40…` is readable by `ps` for the lifetime of the process and lands in your shell history. Use environment variables, or read from a file:

```sh
vulnetix auth login --api-key "$(cat ~/token)" --org-id "$ORG" --store keyring
```

Better, keep it out of argv entirely:

```sh
export VULNETIX_API_KEY="$(cat ~/token)"
export VULNETIX_ORG_ID="$ORG"
vulnetix auth verify
```

## Shell History

```sh
# bash / zsh: a leading space omits the line when HISTCONTROL includes ignorespace
export HISTCONTROL=ignorespace
 export VULNETIX_API_KEY=6e40f1c3…   # note the leading space

# fish: prefix any command to keep it out of history
```

Audit what already leaked:

```sh
grep -nE 'VULNETIX_(API_KEY|API_TOKEN)|VVD_SECRET|--api-key|--secret' \
  ~/.bash_history ~/.zsh_history 2>/dev/null
```

Anything you find must be rotated, not just deleted.
