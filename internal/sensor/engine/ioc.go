package engine

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
)

// IOCSet is the indicators the sensor can check without a rule engine: a
// domain someone resolves or connects to, an address someone connects to, a
// file hash on disk. Each indicator remembers the rule it came from, so a hit
// is reported against that rule.
type IOCSet struct {
	Domains map[string]decide.RuleRef
	IPs     map[string]decide.RuleRef
	Hashes  map[string]decide.RuleRef
}

func newIOCSet() IOCSet {
	return IOCSet{Domains: map[string]decide.RuleRef{}, IPs: map[string]decide.RuleRef{}, Hashes: map[string]decide.RuleRef{}}
}

// Len is the number of indicators.
func (s IOCSet) Len() int { return len(s.Domains) + len(s.IPs) + len(s.Hashes) }

// MatchHost checks a hostname or address, and every parent domain of a
// hostname: an indicator for evil.example covers c2.evil.example.
func (s IOCSet) MatchHost(host string) (decide.RuleRef, string, bool) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		r, ok := s.IPs[ip.String()]

		return r, ip.String(), ok
	}
	for name := host; name != ""; {
		if r, ok := s.Domains[name]; ok {
			return r, name, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
	}

	return decide.RuleRef{}, "", false
}

// MatchHash checks a hex digest of any length the feed carried.
func (s IOCSet) MatchHash(hexDigest string) (decide.RuleRef, bool) {
	r, ok := s.Hashes[strings.ToLower(hexDigest)]

	return r, ok
}

func (s IOCSet) add(r decide.RuleRef, ruleType, body string) (int, error) {
	before := s.Len()
	var err error
	if strings.EqualFold(ruleType, "STIX") {
		err = s.addSTIX(r, body)
	} else {
		err = s.addOpenIOC(r, body)
	}

	return s.Len() - before, err
}

// stixComparison pulls the comparisons out of a STIX pattern:
// [domain-name:value = 'evil.example' OR ipv4-addr:value = '203.0.113.9'].
var stixComparison = regexp.MustCompile(`([a-z0-9-]+):([A-Za-z0-9_.'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'`)

func (s IOCSet) addSTIX(r decide.RuleRef, body string) error {
	var doc struct {
		Type    string `json:"type"`
		Pattern string `json:"pattern"`
		Objects []struct {
			Type    string `json:"type"`
			Pattern string `json:"pattern"`
		} `json:"objects"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return fmt.Errorf("not a STIX bundle or indicator: %w", err)
	}
	patterns := []string{doc.Pattern}
	for _, o := range doc.Objects {
		if o.Type == "indicator" {
			patterns = append(patterns, o.Pattern)
		}
	}
	for _, p := range patterns {
		for _, m := range stixComparison.FindAllStringSubmatch(p, -1) {
			s.put(r, m[1], m[2], strings.ReplaceAll(m[3], `\'`, `'`))
		}
	}

	return nil
}

func (s IOCSet) put(r decide.RuleRef, object, property, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	switch object {
	case "domain-name", "url":
		if object == "url" {
			value = urlHost(value)
		}
		if value != "" {
			s.Domains[strings.TrimSuffix(strings.ToLower(value), ".")] = r
		}
	case "ipv4-addr", "ipv6-addr":
		// A CIDR is not an address; the sensor matches single addresses only.
		if ip := net.ParseIP(value); ip != nil {
			s.IPs[ip.String()] = r
		}
	case "file":
		if strings.HasPrefix(property, "hashes") && isHex(value) {
			s.Hashes[strings.ToLower(value)] = r
		}
	}
}

// addOpenIOC reads IndicatorItem elements whose Context search names a DNS
// host, a remote IP or a file hash.
func (s IOCSet) addOpenIOC(r decide.RuleRef, body string) error {
	dec := xml.NewDecoder(strings.NewReader(body))
	var search string
	inContent := false
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("not OpenIOC XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Context":
				for _, a := range t.Attr {
					if a.Name.Local == "search" {
						search = a.Value
					}
				}
			case "Content":
				inContent = true
			}
		case xml.EndElement:
			if t.Name.Local == "Content" {
				inContent = false
			}
		case xml.CharData:
			if !inContent {
				continue
			}
			value := strings.TrimSpace(string(t))
			lower := strings.ToLower(search)
			switch {
			case strings.Contains(lower, "dnsentryitem/host"), strings.Contains(lower, "network/dns"), strings.HasSuffix(lower, "/hostname"):
				s.put(r, "domain-name", "value", value)
			case strings.Contains(lower, "remoteip"), strings.HasSuffix(lower, "/ip"):
				s.put(r, "ipv4-addr", "value", value)
			case strings.Contains(lower, "md5sum"), strings.Contains(lower, "sha1sum"), strings.Contains(lower, "sha256sum"):
				s.put(r, "file", "hashes", value)
			}
		}
	}
}

func urlHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}

	return raw
}

func isHex(s string) bool {
	if len(s) < 32 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}

	return true
}
