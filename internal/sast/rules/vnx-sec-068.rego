package vulnetix.rules.vnx_sec_068

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-068",
	"name": "Ethereum private key",
	"description": "Reports a hard-coded Ethereum (secp256k1) private key: exactly 64 hexadecimal characters, optionally 0x-prefixed, that are assigned to a private-key name (PRIVATE_KEY, privateKey, DEPLOYER_PRIVATE_KEY, signer_key, wallet_key...) in code, JSON/YAML config or .env files, passed to a wallet or signer constructor (new ethers.Wallet, privateKeyToAccount, Account.from_key, go-ethereum crypto.HexToECDSA, web3j Credentials.create, fromPrivateKey, SigningKey, PrivateKey, Truffle HDWalletProvider, web3.js wallet.add, Rust LocalWallet/PrivateKeySigner from_str or parse), passed as the key argument of signTransaction / sign_transaction, or listed in a Hardhat/Truffle network accounts: [...] array. The key is masked in the snippet. Not reported: other 64-hex values (transaction and block hashes, bytes32 constants, storage slots, Keccak role ids), a key read from the environment, the publicly known Hardhat/Anvil development keys, placeholder or low-entropy values (0x000..., deadbeef...), comment lines, Markdown files, and test, fixture, vendored and generated files. Encrypted V3 keystore files are VNX-SEC-700.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-068/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "ethereum", "crypto", "blockchain", "credentials"],
}

_skip(path) if endswith(lower(path), ".md")

_skip(path) if endswith(lower(path), ".markdown")

_hex := `(?:0x)?([0-9a-fA-F]{64})(?:[^0-9a-fA-FxX]|$)`

# A private-key name, then := / = / :, then the key.
_assigned := concat("", [
	`(?i)(?:priv(?:ate)?[_-]?key|(?:deployer|signer|wallet|owner|operator|relayer|eth|account|minter)[_-]?(?:priv(?:ate)?[_-]?)?key)(?:s|_?hex)?['"]?\s*(?::=|=|:)\s*\[?\s*['"\x60]?`,
	_hex,
])

# A wallet or signer constructor taking the key as a literal.
_constructed := concat("", [
	`(?:\bWallet|privateKeyToAccount|\bfrom_key|\bfromKey|HexToECDSA|Credentials\.create|fromPrivateKey|PrivateKey|SigningKey|ECKeyPair\.create|HDWalletProvider|wallet\.add|(?:Wallet|Signer|SigningKey)::from_str)\s*\(\s*['"\x60]`,
	_hex,
])

# A transaction signed with a literal key as the second argument
# (web3.js signTransaction, web3.py sign_transaction).
_signed := concat("", [`\b(?:signTransaction|sign_transaction)\s*\([^,()]+,\s*['"\x60]`, _hex])

# Rust: a literal parsed into a wallet or signer.
_parsed := `['"](?:0x)?([0-9a-fA-F]{64})['"]\s*\.parse::<\s*(?:LocalWallet|PrivateKeySigner|Wallet\b)`

_parsed_typed := concat("", [`:\s*(?:LocalWallet|PrivateKeySigner)\s*=\s*['"]`, _hex])

# Hardhat / Truffle network accounts array.
_accounts := concat("", [`\baccounts\s*:\s*\[\s*['"\x60]`, _hex])

_patterns := [_assigned, _constructed, _signed, _parsed, _parsed_typed, _accounts]

# Hardhat / Anvil / Ganache default accounts 0-2: published, funded only on
# local development chains.
_well_known := {
	"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
	"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
	"5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
}

_weak(k) if _well_known[lower(k)]

_weak(k) if secrets.is_placeholder(k)

_weak(k) if not secrets.high_entropy(k, 3.0)

_keys(line) := {k |
	some p in _patterns
	some m in regex.find_all_string_submatch_n(p, line, -1)
	k := m[1]
	not _weak(k)
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`[0-9a-fA-F]{64}`, content)
	regex.match(`(?i)key|wallet|account|credential|signer`, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[0-9a-fA-F]{64}`, line)
	not helpers.is_comment_line(line)
	some k in _keys(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hard-coded Ethereum private key; treat the account as compromised, move its funds and load signing keys from a keystore, hardware wallet or secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, k, "***"),
	}
}
