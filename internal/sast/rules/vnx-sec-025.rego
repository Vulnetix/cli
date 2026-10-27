package vulnetix.rules.vnx_sec_025

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-025",
	"name": "Azure Storage Account key hardcoded",
	"description": "Reports an 88-character Azure Storage account key (86 base64 characters and == padding) written literally in a file when the line names it as a storage key: an AccountKey= segment of a connection string, a variable or field such as AZURE_STORAGE_KEY, storage_account_access_key, primary_access_key, access_key (the azurerm backend) or ARM_ACCESS_KEY, the az CLI --account-key flag, or a StorageSharedKeyCredential/StorageCredentials/CloudStorageAccount or Blob/Queue/Table/Share/DataLake service-client call (also when the key is on the next lines of a multi-line call, as in BlobServiceClient(url, credential=...)). The public Azurite/storage-emulator key, placeholder and low-entropy values, environment or template references, and test and fixture paths are not reported; other 88-character base64 values (sha512 integrity hashes, signatures) without that context are not reported either.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-025/",
	"languages": ["generic"],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secret", "azure", "cloud", "credentials"],
}

_token_re := `(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{86}==)(?:[^A-Za-z0-9+/=]|$)`

# The context that makes an 88-character base64 value a storage key.
_line_ctx_re := `(?i)(AccountKey\s*=|azure[_.-]?(storage[_.-]?)?(account[_.-]?)?(access[_.-]?)?key|storage[_.-]?(account[_.-]?)?(access[_.-]?)?key|account[_.-]?key|(primary|secondary)[_.-]?access[_.-]?key|--account-key|StorageSharedKeyCredential|StorageCredentials\s*\(|CloudStorageAccount\s*\(|AZURE_STORAGE_ACCESS_KEY|\baccess[_-]?key\b|\bARM_ACCESS_KEY\b|(Blob|Queue|Table|Share|DataLake|File)Service(Client)?\s*\()`

# A multi-line constructor names the API a couple of lines above the key.
_call_ctx_re := `(StorageSharedKeyCredential|StorageCredentials|AzureNamedKeyCredential|SharedKeyCredential|(Blob|Queue|Table|Share|DataLake|File)Service(Client)?)\s*\(`

# Published Azurite / storage-emulator account key (devstoreaccount1).
_emulator_key := "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

# Cheap whole-file prefilter: every context above contains one of these.
_file_words := ["zure", "ZURE", "torage", "TORAGE", "ccount", "CCOUNT", "ccess_key", "CCESS_KEY", "ccessKey", "SharedKey"]

_file_ctx(content) if {
	some w in _file_words
	contains(content, w)
}

_has_ctx(lines, i, line) if regex.match(_line_ctx_re, line)

_has_ctx(lines, i, line) if {
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(_call_ctx_re, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	contains(content, "==")
	_file_ctx(content)
	regex.match(`[A-Za-z0-9+/]{86}==`, content)
	lines := split(content, "\n")
	# Only the lines holding "==", found in Go; lines stays the whole split
	# so _has_ctx can read the lines above.
	some i, line in vulnetix.lines_containing(content, ["=="])
	m := regex.find_all_string_submatch_n(_token_re, line, -1)
	some hit in m
	token := hit[1]
	token != _emulator_key
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 4.5)
	_has_ctx(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Azure Storage Account key detected; rotate immediately via Azure Portal and store in Azure Key Vault instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
