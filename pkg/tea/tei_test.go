package tea

import "testing"

func TestParseTEIBothSpellings(t *testing.T) {
	const id = "0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"
	const purl = "pkg:github/acme/widget@1.2.3"
	encoded := "cGtnOmdpdGh1Yi9hY21lL3dpZGdldEAxLjIuMw" // base64url, no padding

	cases := []struct {
		name, in string
		want     TEI
		ok       bool
	}{
		{"urn uuid", "urn:tei:uuid:vulnetix.com:" + id, TEI{"uuid", "vulnetix.com", id}, true},
		{"uri uuid", "tei://vulnetix.com/uuid/" + id, TEI{"uuid", "vulnetix.com", id}, true},
		{"urn purl keeps its colons", "urn:tei:purl:vulnetix.com:" + purl, TEI{"purl", "vulnetix.com", purl}, true},
		{"uri purl is decoded", "tei://vulnetix.com/purl/" + encoded, TEI{"purl", "vulnetix.com", purl}, true},
		{"uri purl tolerates padding", "tei://vulnetix.com/purl/" + encoded + "==", TEI{"purl", "vulnetix.com", purl}, true},
		{"case in the scheme and domain", "TEI://Vulnetix.COM/uuid/" + id, TEI{"uuid", "vulnetix.com", id}, true},
		{"surrounding space", "  tei://vulnetix.com/uuid/" + id + "  ", TEI{"uuid", "vulnetix.com", id}, true},
		{"a double-encoded urn", "urn%3Atei%3Auuid%3Avulnetix.com%3A" + id, TEI{"uuid", "vulnetix.com", id}, true},
		{"an encoded slash in the id", "tei://vulnetix.com/uuid/a%2Fb", TEI{"uuid", "vulnetix.com", "a/b"}, true},
		{"missing id", "tei://vulnetix.com/uuid/", TEI{}, false},
		{"an id with a path", "tei://vulnetix.com/uuid/a/b", TEI{}, false},
		{"bad base64 purl", "tei://vulnetix.com/purl/!!!", TEI{}, false},
		{"too few urn parts", "urn:tei:uuid", TEI{}, false},
		{"not a tei", "pkg:npm/lodash", TEI{}, false},
		{"empty", "", TEI{}, false},
	}
	for _, c := range cases {
		got, ok := ParseTEI(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: ParseTEI(%q) = %+v, %v; want %+v, %v", c.name, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestTEISpellingsRoundTrip(t *testing.T) {
	for _, urn := range []string{
		"urn:tei:uuid:vulnetix.com:0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab",
		"urn:tei:purl:vulnetix.com:pkg:github/acme/widget@1.2.3",
	} {
		parsed, ok := ParseTEI(urn)
		if !ok {
			t.Fatalf("%q did not parse", urn)
		}
		uri := parsed.URI()
		back, ok := ParseTEI(uri)
		if !ok || back != parsed {
			t.Errorf("%q -> %q -> %+v, want %+v", urn, uri, back, parsed)
		}
		if back.URN() != urn {
			t.Errorf("%q came back as %q", urn, back.URN())
		}
	}
}

// A server recognises the spelling of the version it speaks, and nothing converts
// a TEI it would have understood.
func TestTEIForVersion(t *testing.T) {
	const urn = "urn:tei:uuid:vulnetix.com:0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"
	const uri = "tei://vulnetix.com/uuid/0f9c6b0e-6a0f-5e0e-9e5e-0123456789ab"

	cases := []struct{ name, in, version, want string }{
		{"a urn to a 1.0.0 server", urn, "1.0.0", uri},
		{"a uri to a 1.0.0 server is left alone", uri, "1.0.0", uri},
		{"a uri to a 0.4.0 server", uri, "0.4.0", urn},
		{"a urn to a 0.4.0 server is left alone", urn, "0.4.0", urn},
		{"an unknown version sends what was typed (uri)", uri, "", uri},
		{"an unknown version sends what was typed (urn)", urn, "", urn},
		{"garbage is never rewritten", "not a tei", "1.0.0", "not a tei"},
	}
	for _, c := range cases {
		if got := TEIForVersion(c.in, c.version); got != c.want {
			t.Errorf("%s: TEIForVersion(%q, %q) = %q, want %q", c.name, c.in, c.version, got, c.want)
		}
	}

	// A purl TEI survives the trip with its encoding intact.
	purlURN := "urn:tei:purl:vulnetix.com:pkg:github/acme/widget@1.2.3"
	if got := TEIForVersion(purlURN, "1.0.0"); got != "tei://vulnetix.com/purl/cGtnOmdpdGh1Yi9hY21lL3dpZGdldEAxLjIuMw" {
		t.Errorf("purl urn to a 1.0.0 server = %q", got)
	}
}

func TestNormaliseDomainReadsEitherTEISpelling(t *testing.T) {
	for in, want := range map[string]string{
		"tei://products.example.com/uuid/abc-123": "products.example.com",
		"TEI://Products.Example.COM/purl/abc":     "products.example.com",
		"urn:tei:uuid:products.example.com:abc":   "products.example.com",
	} {
		got, err := NormaliseDomain(in)
		if err != nil || got != want {
			t.Errorf("NormaliseDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
