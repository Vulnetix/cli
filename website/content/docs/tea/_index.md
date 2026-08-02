---
title: Transparency Exchange API
weight: 11
description: "How to consume the Vulnetix TEA server as another provider: DNS discovery, the OWASP OpenAPI specifications we target (0.4.0), and public unauthenticated example requests with their real responses."
---

The Transparency Exchange API is an OWASP specification for resolving software transparency data — SBOMs, VEX documents, attestations, and where a release is actually obtained — starting from a single identifier and following DNS.

Vulnetix runs a conformant TEA server. This page is for the other side of the exchange: **you are a TEA provider, or building a TEA client, and you want to read what we publish.**

{{< callout type="info" >}}
Every request on this page is public and unauthenticated. Nothing here needs an account, an API key, or an agreement with us. Paste any of them into a terminal and you will get the response shown.
{{< /callout >}}

## The specifications we implement

TEA is developed in the open by the OWASP TEA working group. We track the specification rather than extending it — an implementation that adds fields is not interoperable, it is a dialect.

| Document | Where |
|---|---|
| Consumption API (the contract below) | [CycloneDX/transparency-exchange-api](https://github.com/CycloneDX/transparency-exchange-api) → `spec/openapi.yaml` |
| Publication API (not yet upstream) | [0x73746F66/transparency-exchange-api](https://github.com/0x73746F66/transparency-exchange-api) → `spec/publisher/openapi.yaml` |

**We currently target specification version `0.4.0`**, which is what our discovery document advertises. The publication document is generated from the consumption document so the two cannot drift apart.

## 1. Start at DNS

Resolution starts from a domain, never from a URL somebody handed you. Take the domain out of whatever identifier you hold — a TEI, a purl, a vendor contact — and fetch its discovery document.

```sh
curl https://vulnetix.com/.well-known/tea
```

```json
{
  "schemaVersion": 1,
  "endpoints": [
    {
      "url": "https://www.vulnetix.com/tea",
      "versions": ["0.4.0"],
      "priority": 1
    }
  ]
}
```

- `versions` — the specification versions this server implements.
- `url` — the API root. Append the major version you selected: `https://www.vulnetix.com/tea/v1`.
- `priority` — orders endpoints where a server advertises several.

Every example below uses `https://www.vulnetix.com/tea/v1` as the base.

## 2. Resolve an identifier

If you already hold a TEI, `/discovery` tells you which product release it names and which servers can answer for it. This is the step that lets a client arrive knowing one string and nothing else.

```sh
curl 'https://www.vulnetix.com/tea/v1/discovery\
  ?tei=urn%3Atei%3Auuid%3Avulnetix.com%3A54e8820d-0803-5a4f-858d-88a279486564'
```

```json
[
  {
    "productReleaseUuid": "8b406807-739d-5b4b-aae6-18ffb9e56c17",
    "servers": [
      {
        "rootUrl": "https://www.vulnetix.com/tea/v1",
        "versions": ["0.4.0"]
      }
    ]
  }
]
```

The TEI must be percent-encoded — it contains colons.

## 3. List what we publish

A server that will not say what it publishes cannot be exchanged with, so the catalogue is readable with no credential. Only objects whose publisher marked them public appear here.

```sh
curl 'https://www.vulnetix.com/tea/v1/products?pageSize=2'
```

```json
{
  "hasNext": false,
  "nextPageToken": "",
  "results": [
    {
      "uuid": "54e8820d-0803-5a4f-858d-88a279486564",
      "name": "Vulnetix/cli",
      "identifiers": [
        {
          "idType": "TEI",
          "idValue": "urn:tei:uuid:vulnetix.com:54e8820d-0803-5a4f-858d-88a279486564"
        },
        { "idType": "PURL", "idValue": "pkg:github/Vulnetix/cli" }
      ]
    }
  ]
}
```

Page with `nextPageToken` while `hasNext` is true.

## 4. Walk to a release

A product holds releases. A product release points at the component releases it is assembled from — follow `components[].release`, because that is where the downloads and the evidence live.

```sh
curl 'https://www.vulnetix.com/tea/v1\
  /product/54e8820d-0803-5a4f-858d-88a279486564/releases'
```

```json
{
  "hasNext": false,
  "nextPageToken": "",
  "results": [
    {
      "uuid": "e5fe63be-d3d0-5b7a-a3bc-39525d15cf88",
      "version": "v3.83.0",
      "releaseDate": "2026-08-02T05:55:17Z",
      "components": [
        {
          "uuid": "41714f49-4f06-5a3b-96d4-c83f7d78a270",
          "release": "3e6a317c-6027-5448-abd7-5f260cec7e4b"
        }
      ]
    }
  ]
}
```

## 5. Take the evidence and the downloads

One read returns both halves, and they answer different questions:

- **`distributions`** — how the release is obtained. Binaries with checksums, and install channels like Homebrew or Scoop that have no single file to fetch.
- **`latestCollection`** — the evidence published *about* the release: SBOMs, VEX documents, attestations.

An SBOM is not an answer to "where do I download this", which is why TEA keeps them apart.

```sh
curl 'https://www.vulnetix.com/tea/v1\
  /componentRelease/3e6a317c-6027-5448-abd7-5f260cec7e4b'
```

```json
{
  "release": {
    "uuid": "3e6a317c-6027-5448-abd7-5f260cec7e4b",
    "componentName": "Vulnetix/cli",
    "version": "v3.83.0",
    "identifiers": [
      { "idType": "PURL", "idValue": "pkg:github/Vulnetix/cli@v3.83.0" }
    ],
    "distributions": [
      {
        "distributionId": "c5142319-96cc-5959-ab0b-04e05462a28d",
        "description": "vulnetix-darwin-amd64",
        "url": "https://github.com/Vulnetix/cli/releases/download/v3.83.0/vulnetix-darwin-amd64",
        "checksums": [
          {
            "algType": "SHA-256",
            "algValue": "93d9a6b3ac331b8866f494c56b2be62a2593f18e341cfed8206cf2be37e4b846"
          }
        ]
      },
      {
        "distributionId": "…",
        "description": "Homebrew — brew install Vulnetix/tap/vulnetix",
        "url": "https://github.com/Vulnetix/homebrew-tap"
      }
    ]
  },
  "latestCollection": {
    "version": 1,
    "updateReason": { "type": "INITIAL_RELEASE" },
    "artifacts": [
      {
        "name": "vulnetix.cdx.json",
        "type": "BOM",
        "formats": [
          {
            "mediaType": "application/vnd.cyclonedx+json",
            "url": "https://www.vulnetix.com/tea/v1/artifact/30054fe0-f6f8-58e8-970e-8105568bcd70/1/download"
          }
        ]
      }
    ]
  }
}
```

That release carries 14 distributions in total: one per published binary, plus the install channels. Artifact `url` values are direct downloads and need no credential either.

{{< callout type="warning" >}}
Distribution checksums are the **publisher's** assertion about bytes we do not host. Verify them against the file you fetch — do not treat their presence as proof we checked.
{{< /callout >}}

## Doing it with the CLI

The `tea` command speaks this protocol against any conformant server, not only ours. Point `--server` anywhere:

```sh
vulnetix tea discover vulnetix.com
vulnetix tea products --server https://www.vulnetix.com/tea/v1
vulnetix tea collection 3e6a317c-6027-5448-abd7-5f260cec7e4b
vulnetix tea resolve urn:tei:uuid:vulnetix.com:54e8820d-0803-5a4f-858d-88a279486564
```

Reading a public catalogue needs no credentials. See [`tea` in the CLI reference](../cli-reference/tea/) for publishing your own.

## Authentication

Authentication is **optional**, and it only ever widens what you can see: a credential gets you objects shared with your organisation in addition to the public ones. It is never required to read a public catalogue — that is what makes this an exchange rather than a portal.

If you do send a credential it must be valid. An unrecognised one is refused with `401` rather than quietly downgraded to anonymous, so a stale key fails loudly instead of silently hiding the releases you expected to see.

| Scheme | Header |
|---|---|
| Bearer token | `Authorization: Bearer <token>` |
| API key | `Authorization: ApiKey <orgId>:<hmac>` |
| Basic | `Authorization: Basic base64(orgId:hmac)` |

## What you will not find

- **Objects nobody published.** We serve a projection of scan history to authenticated tenants for their own software. None of that appears in the public catalogue: an inference we drew about somebody else's code is not ours to publish.
- **Anything marked private or shared.** These return `404`, not `403` — telling you an object exists but is not yours is itself a disclosure.
