package tea

import (
	"encoding/base64"
	"net/url"
	"strings"
)

// A TEI has two spellings. TEA 0.x wrote `urn:tei:<type>:<domain>:<id>`, and 1.0.0
// writes `tei://<domain>/<type>/<id>`, where the id is a single path segment and a
// purl is base64url encoded without padding. They name the same thing, but a
// server only recognises the spelling of the version it speaks, so a client that
// is handed one and talks to the other has to convert it.
//
// A TEI is compared exactly as written, so nothing here rewrites one the server
// would have understood: a conversion happens only when the form is the wrong one
// for the version in use.

// TEI is a TEI taken apart. For a purl, ID is the Package URL itself, whichever
// spelling it arrived in.
type TEI struct {
	Type   string
	Domain string
	ID     string
}

// ParseTEI reads either spelling. It reports false for anything that is not a
// well-formed TEI of either.
func ParseTEI(raw string) (TEI, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return TEI{}, false
	}
	// A TEI that was percent-encoded twice on its way here.
	if strings.HasPrefix(strings.ToLower(s), "urn%3a") || strings.HasPrefix(strings.ToLower(s), "tei%3a") {
		if dec, err := url.QueryUnescape(s); err == nil {
			s = dec
		}
	}

	if len(s) > 6 && strings.EqualFold(s[:6], "tei://") {
		parts := strings.Split(s[6:], "/")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return TEI{}, false
		}
		id, err := url.PathUnescape(parts[2])
		if err != nil || id == "" {
			return TEI{}, false
		}
		kind := strings.ToLower(parts[1])
		if kind == "purl" {
			dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(id, "="))
			if err != nil || len(dec) == 0 {
				return TEI{}, false
			}
			id = string(dec)
		}
		return TEI{Type: kind, Domain: strings.ToLower(parts[0]), ID: id}, true
	}

	parts := strings.SplitN(s, ":", 4)
	if len(parts) != 4 || !strings.EqualFold(parts[0], "urn") || !strings.EqualFold(parts[1], "tei") {
		return TEI{}, false
	}
	// The identifier may itself contain colons (a purl always does), so the domain
	// is what precedes the first colon of the remainder and the rest is the id.
	domain, id, ok := strings.Cut(parts[3], ":")
	if !ok || domain == "" || id == "" {
		return TEI{}, false
	}
	return TEI{Type: strings.ToLower(parts[2]), Domain: strings.ToLower(domain), ID: id}, true
}

// URI renders the 1.0.0 spelling.
func (t TEI) URI() string {
	id := t.ID
	if t.Type == "purl" {
		id = base64.RawURLEncoding.EncodeToString([]byte(id))
	} else {
		id = url.PathEscape(id)
	}
	return "tei://" + t.Domain + "/" + t.Type + "/" + id
}

// URN renders the 0.x spelling.
func (t TEI) URN() string {
	return "urn:tei:" + t.Type + ":" + t.Domain + ":" + t.ID
}

// IsURI reports whether a TEI is written in the 1.0.0 spelling.
func IsURI(raw string) bool {
	return len(raw) > 6 && strings.EqualFold(strings.TrimSpace(raw)[:6], "tei://")
}

// TEIForVersion renders a TEI in the spelling a server of the given version
// recognises. An unreadable TEI, and a version the CLI cannot place, are returned
// unchanged: the server's answer to what the user typed is better than a guess.
func TEIForVersion(raw, version string) string {
	t, ok := ParseTEI(raw)
	if !ok {
		return raw
	}
	v, known := normaliseVersion(version)
	switch {
	case !known:
		return raw
	case v.Major() >= 1:
		if IsURI(raw) {
			return raw
		}
		return t.URI()
	default:
		if !IsURI(raw) {
			return raw
		}
		return t.URN()
	}
}
