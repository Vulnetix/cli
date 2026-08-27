package cdx

import "testing"

// A component hash that is not a hex digest of the algorithm's exact length
// fails CycloneDX schema validation, and a failed validation discards the whole
// document — so one malformed npm `integrity` string used to cost the user
// their entire SBOM. hexDigest is the guard; these cases pin it.
func TestHexDigest(t *testing.T) {
	const sha512Hex = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

	cases := []struct {
		name  string
		alg   string
		value string
		want  string
		ok    bool
	}{
		{"hex sha-512 passes through", "SHA-512", sha512Hex, sha512Hex, true},
		{"upper-case hex is lowered", "SHA-256", "AB" + repeat("cd", 31), "ab" + repeat("cd", 31), true},
		{"npm SRI base64 is decoded", "SHA-512",
			"z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==",
			sha512Hex, true},
		{"truncated base64 is refused", "SHA-512",
			"ZmdL2aui+eN/ftocBGW3G2HQk/3WZJ7iV1qlB2cCAhdR0V+ablGHHBI4vj2Gj6HJYRg6oesTMonFd5fn1LGzQ==", "", false},
		{"right-length wrong-alphabet is refused", "SHA-256", repeat("zz", 32), "", false},
		{"empty is refused", "SHA-256", "   ", "", false},
		{"unknown alg is refused", "H1", sha512Hex, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := hexDigest(tc.alg, tc.value)
			if ok != tc.ok {
				t.Fatalf("hexDigest(%q, %q) ok = %v, want %v", tc.alg, tc.value, ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("hexDigest(%q, %q) = %q, want %q", tc.alg, tc.value, got, tc.want)
			}
		})
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}
