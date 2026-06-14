# SPDX-License-Identifier: Apache-2.0
# Shared helpers for high-fidelity secret-detection rules.
#
# Detection pipeline used by every vnx-sec rule (cheapest gate first):
#   skip_path  ->  has_keyword / prefix contains  ->  regex token extract
#   ->  is_placeholder allowlist  ->  shannon_entropy threshold  ->  finding
#
# This package is imported by embedded secrets rules via
#   import data.vulnetix.lib.secrets
# It has no metadata/findings, so the engine never enumerates it as a rule, and
# the website rule extractor skips everything under _lib/.

package vulnetix.lib.secrets

import rego.v1

# --- path suppression -------------------------------------------------------
# Generated/minified/vendored/test artifacts are high-noise and rarely hold
# real production credentials.
_skip_suffix := [
	".lock", ".sum", ".min.js", ".min.css", ".min.html", ".min.json",
	".map", ".svg", ".snap", ".pb.go", ".woff", ".woff2", ".ttf", ".eot",
	"_test.go", ".spec.ts", ".spec.js", ".test.ts", ".test.js",
]

_skip_substr := [
	"/testdata/", "/fixtures/", "/node_modules/", "/vendor/",
	"/.terraform/", "/dist/", "/build/", "/__snapshots__/",
]

skip_path(p) if {
	some s in _skip_suffix
	endswith(p, s)
}

skip_path(p) if {
	some s in _skip_substr
	contains(p, s)
}

# --- keyword prefilter ------------------------------------------------------
# Cheap contains() gate that must pass before a rule runs its regex. `kws` is a
# list of lower-case substrings; the line matches if any is present.
has_keyword(line, kws) if {
	low := lower(line)
	some k in kws
	contains(low, k)
}

# --- placeholder / stopword allowlist ---------------------------------------
_stopwords := [
	"example", "examplekey", "placeholder", "redacted", "your-", "<your",
	"changeme", "change-me", "dummy", "sample", "testkey", "test-key",
	"xxxxxx", "000000", "aaaaaa", "111111", "deadbeef", "abcdef",
	"1234567890", "notreal", "fakekey", "fake-key", "lorem", "foobar",
	"insert", "replace", "todo", "n/a", "none",
]

# A token is a placeholder if it contains a known stopword, is a single
# repeated character run, or is a canonical example UUID.
is_placeholder(tok) if {
	low := lower(tok)
	some w in _stopwords
	contains(low, w)
}

# RE2 (used by OPA regex.match) has no backreferences, so common single-char
# placeholder runs are enumerated explicitly. Real high-entropy tokens are also
# caught by the entropy gate; this covers fixed-prefix rules that skip entropy.
is_placeholder(tok) if regex.match(`(?i)(x{6,}|a{6,}|0{6,}|1{6,}|z{6,}|\.{4,}|-{4,}|_{4,})`, tok)

is_placeholder(tok) if regex.match(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, tok)

# AWS and similar tools mint deterministic example tokens ending in EXAMPLE.
is_example_token(tok) if is_placeholder(tok)

is_example_token(tok) if endswith(upper(tok), "EXAMPLE")

# --- entropy ----------------------------------------------------------------
# Thin wrapper over the Go-registered vulnetix.shannon_entropy builtin.
high_entropy(tok, threshold) if vulnetix.shannon_entropy(tok) >= threshold

# --- snippet redaction ------------------------------------------------------
# Mask long credential-shaped runs so the SARIF snippet does not re-leak the
# secret it reports.
redact(line) := regex.replace(line, `[A-Za-z0-9+/=_\-]{12,}`, "***REDACTED***")
