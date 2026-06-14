---
title: "Secrets — Crypto & Blockchain"
description: "Ethereum, Bitcoin and other blockchain private keys and wallet credentials."
weight: 12
---

Ethereum, Bitcoin and other blockchain private keys and wallet credentials.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-652"></a>VNX-SEC-652 | Bitcoin WIF private key | Critical | keyword + regex |
| <a id="vnx-sec-653"></a>VNX-SEC-653 | BIP39 mnemonic seed phrase | Critical | keyword + regex |
| <a id="vnx-sec-654"></a>VNX-SEC-654 | Solana keypair byte array | Critical | keyword + regex |
| <a id="vnx-sec-655"></a>VNX-SEC-655 | Tron (TRX) private key | Critical | keyword + regex |
| <a id="vnx-sec-656"></a>VNX-SEC-656 | Infura project ID | Medium | keyword + regex + entropy |
| <a id="vnx-sec-657"></a>VNX-SEC-657 | Infura project secret | High | keyword + regex + entropy |
| <a id="vnx-sec-658"></a>VNX-SEC-658 | Alchemy auth token (alcht_) | High | keyword + regex |
| <a id="vnx-sec-659"></a>VNX-SEC-659 | Alchemy API key | High | keyword + regex + entropy |
| <a id="vnx-sec-660"></a>VNX-SEC-660 | QuickNode API token | High | keyword + regex + entropy |
| <a id="vnx-sec-661"></a>VNX-SEC-661 | Moralis API key | High | keyword + regex + entropy |
| <a id="vnx-sec-662"></a>VNX-SEC-662 | Etherscan API key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-663"></a>VNX-SEC-663 | BscScan API key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-664"></a>VNX-SEC-664 | PolygonScan API key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-665"></a>VNX-SEC-665 | Blockchain.com API key | High | keyword + regex |
| <a id="vnx-sec-666"></a>VNX-SEC-666 | Coinbase Wallet API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-667"></a>VNX-SEC-667 | Binance API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-668"></a>VNX-SEC-668 | Binance API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-669"></a>VNX-SEC-669 | Kraken API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-670"></a>VNX-SEC-670 | Kraken private API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-671"></a>VNX-SEC-671 | Bitfinex API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-672"></a>VNX-SEC-672 | Tatum API key | High | keyword + regex |
| <a id="vnx-sec-673"></a>VNX-SEC-673 | thirdweb secret key (sk_) | High | keyword + regex + entropy |
| <a id="vnx-sec-674"></a>VNX-SEC-674 | WalletConnect project ID | Medium | keyword + regex + entropy |
| <a id="vnx-sec-698"></a>VNX-SEC-698 | BscScan/Etherscan-family multichain key (V2) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-699"></a>VNX-SEC-699 | Coinbase API key (organizations/ EC key name) | High | keyword + regex |
| <a id="vnx-sec-700"></a>VNX-SEC-700 | Ethereum keystore JSON (V3 wallet) | High | keyword + regex |
| <a id="vnx-sec-706"></a>VNX-SEC-706 | Bitcoin testnet WIF private key | Medium | keyword + regex |
| <a id="vnx-sec-707"></a>VNX-SEC-707 | Solana base58 secret key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-708"></a>VNX-SEC-708 | Helius API key | High | keyword + regex |
| <a id="vnx-sec-713"></a>VNX-SEC-713 | OKX API passphrase | Critical | keyword + regex + entropy |
| <a id="vnx-sec-714"></a>VNX-SEC-714 | OKX API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-715"></a>VNX-SEC-715 | Bybit API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-716"></a>VNX-SEC-716 | Bybit API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-717"></a>VNX-SEC-717 | Gemini exchange API key (account-/master-) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-718"></a>VNX-SEC-718 | Dune Analytics API key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-719"></a>VNX-SEC-719 | Pinata JWT (IPFS) | High | keyword + regex |
| <a id="vnx-sec-724"></a>VNX-SEC-724 | Coinbase Commerce API key | High | keyword + regex |
| <a id="vnx-sec-725"></a>VNX-SEC-725 | Ankr API key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-733"></a>VNX-SEC-733 | Bittrex/legacy exchange API secret | High | keyword + regex + entropy |
| <a id="vnx-sec-734"></a>VNX-SEC-734 | KuCoin API passphrase | Critical | keyword + regex + entropy |
| <a id="vnx-sec-735"></a>VNX-SEC-735 | CoinMarketCap API key | Medium | keyword + regex |
| <a id="vnx-sec-981"></a>VNX-SEC-981 | Coinbase CDP API key ID (organizations path) | High | keyword + regex |
| <a id="vnx-sec-982"></a>VNX-SEC-982 | Coinbase CDP EC private key (PEM, assignment) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-983"></a>VNX-SEC-983 | Kraken API secret (base64 private key) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-984"></a>VNX-SEC-984 | Gemini API secret (master/account secret) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-985"></a>VNX-SEC-985 | KuCoin API key | High | keyword + regex + entropy |
| <a id="vnx-sec-986"></a>VNX-SEC-986 | KuCoin API secret (UUID) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-987"></a>VNX-SEC-987 | OKX API key (UUID) | High | keyword + regex + entropy |
| <a id="vnx-sec-988"></a>VNX-SEC-988 | Bitstamp API key | High | keyword + regex + entropy |
| <a id="vnx-sec-989"></a>VNX-SEC-989 | Bitstamp API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-990"></a>VNX-SEC-990 | Gate.io API key | High | keyword + regex + entropy |
| <a id="vnx-sec-991"></a>VNX-SEC-991 | Gate.io API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-992"></a>VNX-SEC-992 | Crypto.com Exchange API key | High | keyword + regex + entropy |
| <a id="vnx-sec-993"></a>VNX-SEC-993 | Crypto.com Exchange API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-994"></a>VNX-SEC-994 | Huobi/HTX API key | High | keyword + regex + entropy |
| <a id="vnx-sec-995"></a>VNX-SEC-995 | Huobi/HTX secret key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-996"></a>VNX-SEC-996 | MEXC API key | High | keyword + regex + entropy |
| <a id="vnx-sec-997"></a>VNX-SEC-997 | MEXC API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-998"></a>VNX-SEC-998 | Deribit client ID | High | keyword + regex + entropy |
| <a id="vnx-sec-999"></a>VNX-SEC-999 | Deribit client secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1000"></a>VNX-SEC-1000 | dYdX API key (UUID) | High | keyword + regex + entropy |
| <a id="vnx-sec-1001"></a>VNX-SEC-1001 | dYdX API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1002"></a>VNX-SEC-1002 | Fireblocks API key (UUID) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1003"></a>VNX-SEC-1003 | Fireblocks API secret (RSA private key) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1004"></a>VNX-SEC-1004 | BitGo access token (v2x) | Critical | keyword + regex |
| <a id="vnx-sec-1005"></a>VNX-SEC-1005 | Anchorage API key (assignment) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1006"></a>VNX-SEC-1006 | Circle USDC API key (live) | Critical | keyword + regex |
| <a id="vnx-sec-1007"></a>VNX-SEC-1007 | Chainalysis API key (assignment) | High | keyword + regex + entropy |
| <a id="vnx-sec-1008"></a>VNX-SEC-1008 | TRM Labs API key (assignment) | High | keyword + regex + entropy |
| <a id="vnx-sec-1009"></a>VNX-SEC-1009 | web3.storage API token (legacy JWT, assignment) | High | keyword + regex + entropy |
| <a id="vnx-sec-1010"></a>VNX-SEC-1010 | Pinata API key (legacy, assignment) | High | keyword + regex + entropy |
| <a id="vnx-sec-1011"></a>VNX-SEC-1011 | Pinata API secret (legacy, assignment) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1012"></a>VNX-SEC-1012 | NFT.storage API token (JWT, assignment) | High | keyword + regex + entropy |
| <a id="vnx-sec-1013"></a>VNX-SEC-1013 | Crossmint API key (server-side) | Critical | keyword + regex |
| <a id="vnx-sec-1014"></a>VNX-SEC-1014 | Binance API secret (assignment, alt context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1015"></a>VNX-SEC-1015 | Bybit API secret (assignment, alt context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1016"></a>VNX-SEC-1016 | KuCoin API secret (passphrase-paired, alt context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-1017"></a>VNX-SEC-1017 | Bitfinex API secret (assignment, alt context) | Critical | keyword + regex + entropy |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
