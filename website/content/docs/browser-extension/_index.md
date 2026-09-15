---
title: "Browser extension"
weight: 13
description: "Hover any vulnerability identifier on any page for VDB intelligence, and list every identifier on the page in a browser sidebar. Install from the Chrome Web Store or Firefox Add-ons."
---

The Vulnetix browser extension puts VDB intelligence where you already read
about vulnerabilities: advisories, changelogs, issue trackers, vendor bulletins,
Slack in a browser tab. It finds vulnerability identifiers in the page text and
gives you two ways to read them.

**Hover card.** Detected identifiers get a dotted underline. Hovering one shows
severity, title, affected package, age, KEV and ransomware status, exploit
maturity and PoC counts — the same summary the Resolve console shows.

**Sidebar.** A real browser sidebar (side panel on Chromium, sidebar on Firefox)
listing every identifier found on the page, sortable by severity, KEV or
publication date and filterable to KEV, malware, high-and-above, or
has-a-known-exploit.

Both link straight through to the
[Resolve console](https://www.vulnetix.com/resolve/lookup) for the full
researcher view.

Over 30 identifier formats are recognised, including `CVE`, `GHSA`, `PYSEC`,
`RUSTSEC`, `GO`, `OSV`, `MAL`, `RHSA`, `USN`, `DSA`, `ALSA`, `SNYK`, `ZDI`,
`EUVD`, `ICSA` and `CNVD`. Identifiers split across markup — a link that breaks
`CVE-2024-3094` in half — are still matched.

## Install

### Chromium (Chrome, Edge, Brave, Arc, Opera, Vivaldi)

Install from the
[Chrome Web Store](https://chromewebstore.google.com/detail/vulnetix/mfopdnbogadgchlpfjmfehcococbdbdd)
and choose **Add to Chrome**. Edge, Brave, Arc, Opera and Vivaldi all install
Chrome Web Store extensions directly: Edge asks once for permission to allow
extensions from other stores, and Opera may prompt to install its Chrome
extension bridge. Updates arrive on their own from there.

Pin the Vulnetix icon to the toolbar. Clicking it opens the sidebar.

### Firefox

Install from
[Firefox Add-ons](https://addons.mozilla.org/firefox/addon/vulnetix/) and choose
**Add to Firefox**. The build there has been through Mozilla review and is
signed, so it installs permanently and updates itself. Firefox ESR, Zen,
LibreWolf and Waterfox install the same add-on from the same page.

Firefox 128 ESR and newer are supported. The toolbar button toggles the sidebar.

### Install without a store

Every release still publishes the files, for an environment where store installs
are blocked by policy or unavailable. A sideloaded copy does **not** update
itself, so prefer the store unless you have a reason not to.

For Chromium, download `vulnetix-chrome.zip` from the
[latest release](https://github.com/Vulnetix/browser-extension/releases/latest),
unzip it, then:

1. Open `chrome://extensions` (or `edge://extensions`, `brave://extensions`)
2. Turn on **Developer mode**
3. Choose **Load unpacked** and select the unzipped folder

A `.zip` cannot be dragged onto the extensions page the way a `.crx` can, so
**Load unpacked** is the route.

For Firefox, download `vulnetix-firefox.xpi`, which is signed by Mozilla and
installs permanently:

1. Open **Add-ons and themes** (`about:addons`)
2. Click the gear icon, then **Install Add-on From File**
3. Select the `.xpi`

`vulnetix-firefox.zip` is the *unsigned* build. Firefox will only load it
temporarily, via `about:debugging#/runtime/this-firefox` → **Load Temporary
Add-on**, and it disappears on restart. Use the `.xpi` unless you are debugging.

### Verify the download

Every release ships `SHA256SUMS.txt`:

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing
```

While the repository is private these downloads need a GitHub session with
access. The `/releases/latest/download/` links are the web route and
authenticate with a browser session, so a signed-in browser fetches them and a
bare `curl` gets a 404 — a token does not help there, because that route
ignores it. For scripts, use the GitHub CLI:

```sh
gh release download --repo Vulnetix/browser-extension \
  --pattern 'vulnetix-chrome.zip' --pattern 'SHA256SUMS.txt'
```

Where `gh` is unavailable, the REST asset endpoint does accept a token, as long
as you ask for the bytes rather than the metadata:

```sh
url=$(gh api repos/Vulnetix/browser-extension/releases/latest \
  --jq '.assets[] | select(.name == "vulnetix-chrome.zip") | .url')
curl -sSL -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/octet-stream" -o vulnetix-chrome.zip "$url"
```

### Store listings

- [Chrome Web Store](https://chromewebstore.google.com/detail/vulnetix/mfopdnbogadgchlpfjmfehcococbdbdd)
  — Chrome, Edge, Brave, Arc, Opera, Vivaldi and Chromium
- [Firefox Add-ons](https://addons.mozilla.org/firefox/addon/vulnetix/) —
  Firefox, Firefox ESR, Zen, LibreWolf and Waterfox

Edge Add-ons publishing is wired up and runs from a release, but that listing is
not live yet. Edge installs the Chrome Web Store build in the meantime.

## Sign in

The extension needs a VDB credential before it can look anything up. Detection
still runs without one, and the Resolve console links always work.

Open the sidebar and choose **Sign in**, or open the extension's options page.
Two methods:

**Sign in with your browser** — the device-code flow. The extension shows an
eight-character code and opens
[vulnetix.com/cli-login-code](https://www.vulnetix.com/cli-login-code); approve
it from a session you are already signed in to. This is the same flow
[`vulnetix auth login`](../authentication/) uses, and it stores the same kind of
long-lived API key, so there is no token to refresh.

**Paste an API key** — for a key you already hold. It is verified against the
VDB before it is stored, so a typo is rejected rather than saved.

Signing out clears the credential and the cached data together.

## Lookups and your quota

Detecting identifiers costs nothing. Looking them up spends VDB requests, and
the quota is per day and hard-capped on the Community plan, so the extension
never fetches speculatively:

| What you do | What it fetches |
| --- | --- |
| Hover an identifier | Just that one |
| Open the sidebar | The page's identifiers, 25 at a time, with **Load more** |
| Turn on *Prefetch on page load* in Settings | Everything, as the page loads. Off by default. |

Results are cached for 24 hours, so hovering the same CVE again is free. The
sidebar shows your remaining quota and when it resets. If you do run out, the
extension degrades to a linker: the card tells you how long until reset and the
Resolve console link keeps working.

## What it sends

Only identifiers, and only when you ask for one. Never the page URL, the page
content, your history, or anything you type — the scanner skips input fields,
text areas and editable regions entirely. There is no telemetry and no
analytics.

The extension talks to `api.vdb.vulnetix.com` and `www.vulnetix.com` and nothing
else. Requests come from the extension's background worker, so no web page ever
sees your API key.

It runs on all `http` and `https` pages because an identifier can appear on any
of them, which is why the browser shows the broad permission warning at install.
`*.vulnetix.com` is excluded — that site renders this data natively. You can
disable individual sites in Settings, or invert it entirely with **only run on
sites I allow**.

## Settings

- **Prefetch on page load** — trade quota for instant hovers
- **Open the sidebar automatically** when identifiers are found. Firefox only:
  Chromium requires a click to open a side panel, so there it shows a count
  badge on the toolbar icon instead
- **Sites** — per-origin disable list, or an allow-list
- **Batch size** and **concurrent requests**
- **Cache** — entry count, size on disk, and a clear button
