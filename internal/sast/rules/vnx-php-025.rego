package vulnetix.rules.vnx_php_025

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-025",
	"name": "PHP deprecated mcrypt encryption functions",
	"description": "A call to a PHP mcrypt function that performs or sets up encryption: mcrypt_encrypt(), mcrypt_decrypt(), the legacy mode functions mcrypt_cbc/cfb/ecb/ofb(), mcrypt_module_open(), mcrypt_generic(), mdecrypt_generic() and mcrypt_create_iv(), called directly (optionally as \\mcrypt_...) or by name through call_user_func()/call_user_func_array(). mcrypt was deprecated in PHP 7.1 and removed in 7.2; libmcrypt has been unmaintained since 2007, offers no authenticated mode and is usually used with DES, 3DES, Blowfish or ECB. Migrate to openssl_encrypt/decrypt with AES-256-GCM or to Sodium. Not reported: the mcrypt helper calls that only size or tear down a cipher (mcrypt_get_iv_size, mcrypt_enc_get_*, mcrypt_generic_init/deinit, mcrypt_module_close), so one encryption is one finding; methods or functions that merely share the name ($obj->mcrypt_encrypt(), Class::mcrypt_decrypt(), my_mcrypt_encrypt()); polyfill definitions (function mcrypt_encrypt(...)); function_exists/extension_loaded checks and other mentions inside string literals or comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-025/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-20"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["weak-crypto", "mcrypt", "deprecated", "php"],
}

_fn := `(?:mcrypt_(?:encrypt|decrypt|cbc|cfb|ecb|ofb|module_open|generic|create_iv)|mdecrypt_generic)`

# A direct call: not a method (->, ::), not part of a longer name, not a
# definition (function mcrypt_encrypt).
_call_re := concat("", [`(?:^|[^\w$>:\\]|[^\w\\]\\)`, _fn, `\s*\(`])

_callback_re := concat("", [`\bcall_user_func(?:_array)?\s*\(\s*['"]\\?`, _fn, `['"]`])

# Remove string literals and trailing // or # comments before matching a call.
_code(line) := c if {
	s := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, "''")
	c := regex.replace(s, `(?://|#).*$`, "")
}

_hit(line) if {
	c := _code(line)
	regex.match(_call_re, c)
	not regex.match(concat("", [`\bfunction\s+&?\s*`, _fn, `\s*\(`]), c)
}

_hit(line) if regex.match(_callback_re, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "crypt_")
	regex.match(`m(?:de)?crypt_`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "crypt_")
	not helpers.is_comment_line(line)
	_hit(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Deprecated mcrypt function detected; mcrypt was removed in PHP 7.2 and offers no authenticated encryption. Migrate to openssl_encrypt/decrypt with AES-256-GCM or the Sodium extension",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
