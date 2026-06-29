package cbom

import (
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// detectSource scans source files for cryptographic API usage. Two mechanisms:
//   - per-algorithm source_patterns, gated by the file's language, attribute an
//     algorithm directly (e.g. Go `crypto/sha256`, Python `hashlib.sha256`).
//   - generic call_extractors capture an algorithm token from a crypto API call
//     (createHash('…'), Cipher.getInstance("…"), "alg":"…") and resolve it through
//     the normalized alias index, so SHA256/Sha256/SHA_256 all map to one asset.
func (c *collector) detectSource(input *sast.ScanInput) {
	if input == nil {
		return
	}
	for path, content := range input.FileContents {
		langs := sast.LanguagesForPath(path)
		if len(langs) == 0 {
			continue
		}
		for i := range c.cat.Algorithms {
			a := &c.cat.Algorithms[i]
			for lang, res := range a.Source {
				if !langs[lang] {
					continue
				}
				for _, re := range res {
					for _, m := range matchLines(content, re) {
						c.addAlgo(a, cdx.CryptoEvidence{
							Method: "source", Category: "api", Locator: locOf(path, m.line), Snippet: m.text,
						}, "", "", "")
					}
				}
			}
		}
		for i := range c.cat.Extractors {
			ex := &c.cat.Extractors[i]
			if ex.Languages != nil && !intersectLangs(ex.Languages, langs) {
				continue
			}
			for _, sm := range findCaptures(content, ex.Re) {
				c.applyExtractor(ex.Role, sm.value, path, sm.line)
			}
		}
	}
}

// applyExtractor resolves a captured token to an algorithm (and, for Java-style
// transforms, a mode/padding) and records it.
func (c *collector) applyExtractor(role, token, path string, line int) {
	switch role {
	case "transform": // e.g. "AES/CBC/PKCS5Padding"
		parts := strings.Split(token, "/")
		var mode, padding string
		if len(parts) > 1 {
			mode = normalizeMode(parts[1])
		}
		if len(parts) > 2 {
			padding = normalizePadding(parts[2])
		}
		if a, ok := c.cat.Lookup(parts[0]); ok {
			c.addAlgo(a, cdx.CryptoEvidence{
				Method: "source", Category: "call", Locator: locOf(path, line), Snippet: token,
			}, "", mode, padding)
		}
	case "jwt":
		if a, ok := c.cat.Lookup(token); ok {
			c.addAlgo(a, cdx.CryptoEvidence{
				Method: "source", Category: "jwt", Locator: locOf(path, line), Snippet: "alg=" + token,
			}, "", "", "")
		}
	default: // "algorithm"
		c.addByToken(token, "source", "call", path, line)
	}
}

// addByToken resolves a possibly-compound token (e.g. "aes-256-gcm") to an
// algorithm, peeling a trailing key size and mode off the canonical base.
func (c *collector) addByToken(token, method, category, path string, line int) {
	ev := cdx.CryptoEvidence{Method: method, Category: category, Locator: locOf(path, line), Snippet: token}
	if a, ok := c.cat.Lookup(token); ok {
		c.addAlgo(a, ev, "", "", "")
		return
	}
	parts := strings.FieldsFunc(token, func(r rune) bool {
		return r == '-' || r == '_' || r == '/' || r == '.'
	})
	if len(parts) == 0 {
		return
	}
	a, ok := c.cat.Lookup(parts[0])
	if !ok {
		return
	}
	var paramSet, mode string
	for _, p := range parts[1:] {
		switch {
		case isDigits(p):
			paramSet = p
		case normalizeMode(p) != "":
			mode = normalizeMode(p)
		}
	}
	c.addAlgo(a, ev, paramSet, mode, "")
}
