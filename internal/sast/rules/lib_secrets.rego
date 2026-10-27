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
	".spec.tsx", ".spec.jsx", ".test.tsx", ".test.jsx",
	"Test.java", "Tests.java", "Test.kt", "Tests.kt", "_test.py", "_spec.rb",
]

_skip_substr := [
	"/testdata/", "/fixtures/", "/node_modules/", "/vendor/",
	"/.terraform/", "/dist/", "/build/", "/__snapshots__/",
	"/__tests__/", "/src/test/",
]

skip_path(p) if {
	some s in _skip_suffix
	endswith(p, s)
}

# Paths are relative to the scan root, so a directory at the top of the tree
# ("testdata/certs/key.pem") has no leading slash: anchor with one before
# matching, or every root-level testdata/, fixtures/, dist/ and build/ is
# scanned as production code.
skip_path(p) if {
	anchored := concat("", ["/", p])
	some s in _skip_substr
	contains(anchored, s)
}

# --- keyword prefilter ------------------------------------------------------
# Cheap contains() gate that must pass before a rule runs its regex. `kws` is a
# list of lower-case substrings; the line matches if any is present. The
# builtin is `some k in kws; contains(lower(line), k)`, computed in Go, with a
# file's lower case computed once per evaluation however many rules ask.
has_keyword(line, kws) if vulnetix.contains_any_fold(line, kws)

# The lines of split(text, "\n") on which has_keyword holds, keyed by their
# index. `some i, line in keyword_lines(content, kws)` visits exactly the
# lines that `some i, line in split(content, "\n"); has_keyword(line, kws)`
# does, without interpreting a loop over every line of the file.
keyword_lines(text, kws) := vulnetix.keyword_lines(text, kws)

# The lines of split(text, "\n") that the regular expression matches, keyed by
# their index: regex.match(pattern, line) over each line, in Go.
pattern_lines(text, pattern) := vulnetix.pattern_lines(text, pattern)

# --- placeholder / stopword allowlist ---------------------------------------
# Runs of one character ("xxxxxx", "000000") are not stopwords: they are judged
# by their share of the token below, so a long real token that contains one
# (every Twitter/X app bearer token opens with twenty-odd "A"s) still reports.
_stopwords := [
	"example", "examplekey", "placeholder", "redacted", "your-", "<your",
	"changeme", "change-me", "dummy", "sample", "testkey", "test-key",
	"deadbeef", "abcdef",
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
# A filler character (x, a, 0, 1, z) in a run is a placeholder when it makes up
# 40% of the token's letters and digits ("AKIAXXXXXXXXXXXXXXXX", "ghp_000000…",
# "access-sandbox-xxxxxxxx-xxxx-…"). A run inside a long real
# token is not: every Twitter/X app bearer token begins with twenty-odd "A"s,
# and testing for any run of six made that rule unable to fire.
is_placeholder(tok) if {
	regex.match(`(?i)(x{6,}|a{6,}|0{6,}|1{6,}|z{6,})`, tok)
	low := lower(tok)
	alnum := count(regex.replace(low, `[^a-z0-9]`, ""))
	alnum > 0
	some c in ["x", "a", "0", "1", "z"]
	(count(split(low, c)) - 1) * 10 >= alnum * 4
}

# Punctuation runs ("....", "----", "____") are placeholders in a token body,
# but PEM blocks are armoured with "-----BEGIN … -----" and SSH2 keys with
# "---- BEGIN … ----": testing the armour made every private-key rule unable
# to fire. Strip it first.
is_placeholder(tok) if {
	body := regex.replace(tok, `-{4,5} ?(BEGIN|END)[A-Z0-9 ]*?-{4,5}`, "")
	regex.match(`(\.{4,}|-{4,}|_{4,})`, body)
}

# Example UUIDs, not every UUID. Matching any UUID here silenced every rule
# whose credential is a UUID (Postmark, Scaleway, Railway, Codecov, Heroku
# legacy keys): a real key of that shape was always "a placeholder".
is_placeholder(tok) if regex.match(`(?i)^(0{8}-0{4}-0{4}-0{4}-0{12}|1{8}-1{4}-1{4}-1{4}-1{12}|f{8}-f{4}-f{4}-f{4}-f{12}|123e4567-e89b-12d3-a456-426614174000|12345678-1234-1234-1234-123456789012|12345678-1234-5678-1234-567812345678|00112233-4455-6677-8899-aabbccddeeff|01234567-89ab-cdef-0123-456789abcdef)$`, tok)

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
