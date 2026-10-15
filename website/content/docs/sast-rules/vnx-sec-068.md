---
title: "VNX-SEC-068 – Ethereum Private Key"
description: "Detects 64-hex Ethereum private keys assigned to a private-key name, passed to a wallet, signer or transaction-signing call, or listed in a Hardhat accounts array."
---

## Overview

This rule reports exactly 64 hexadecimal characters (optionally `0x`-prefixed) used as an Ethereum private key: assigned to a private-key name (`PRIVATE_KEY`, `privateKey`, `DEPLOYER_PRIVATE_KEY`, `signer_key`...) in code, JSON/YAML or `.env` files; passed to `new ethers.Wallet`, `privateKeyToAccount`, `Account.from_key`, go-ethereum `crypto.HexToECDSA`, web3j `Credentials.create`, `fromPrivateKey`, `SigningKey`, `PrivateKey`, Truffle `HDWalletProvider`, web3.js `wallet.add`, or Rust `LocalWallet`/`PrivateKeySigner` (`from_str`, `.parse::<LocalWallet>()`); passed as the key argument of `signTransaction` / `sign_transaction`; or listed in a Hardhat/Truffle `accounts: [...]` array. The key is masked in the snippet.

A bare 64-hex value is not a key: transaction and block hashes, `bytes32` constants, storage slots and role ids are not reported. Neither are keys read from the environment, the published Hardhat/Anvil development keys, placeholders (`0x000...`), comment lines, Markdown, and test, fixture, vendored and generated files. Encrypted V3 keystore files are VNX-SEC-700.

## What Gets Flagged

```js
const wallet = new ethers.Wallet("0x<64 hex characters>", provider);
```

```sh
DEPLOYER_PRIVATE_KEY=<64 hex characters>
```

Not flagged:

```js
const TX_HASH = "0x<64 hex transaction hash>";
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
```

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded ethereum private key values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
