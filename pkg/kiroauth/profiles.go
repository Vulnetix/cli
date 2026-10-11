package kiroauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Profile is one CodeWhisperer profile the signed-in account can use.
type Profile struct {
	ARN  string
	Name string
}

// Region returns the region the profile's ARN names, or "" when the ARN is
// malformed.
func (p Profile) Region() string { return ARNRegion(p.ARN) }

// ARNRegion returns the region field of an arn:aws:codewhisperer ARN, or ""
// when it is not a well-formed CodeWhisperer ARN in a valid region.
func ARNRegion(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") || parts[2] != "codewhisperer" {
		return ""
	}
	if !ValidRegion(parts[3]) {
		return ""
	}
	return parts[3]
}

const (
	maxProfilesBody = 256 << 10
	maxProfiles     = 50
)

// ProfilesBaseURL is the CodeWhisperer control endpoint for region.
func ProfilesBaseURL(region string) string {
	if !ValidRegion(region) {
		region = DefaultRegion
	}
	return "https://codewhisperer." + region + ".amazonaws.com"
}

// ListProfiles asks the CodeWhisperer service which profiles accessToken may
// use. base must pass AllowedAPIURL. Redirects are refused.
func ListProfiles(ctx context.Context, client *http.Client, base, accessToken string) ([]Profile, error) {
	base = strings.TrimRight(base, "/")
	if !AllowedAPIURL(base) {
		return nil, fmt.Errorf("refusing to send a Kiro token to %q", base)
	}
	c := noRedirect(client)
	var out []Profile
	next := ""
	for page := 0; page < 5; page++ {
		body := map[string]any{"maxResults": 10}
		if next != "" {
			body["nextToken"] = next
		}
		payload, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("X-Amz-Target", "AmazonCodeWhispererService.ListAvailableProfiles")
		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("list kiro profiles: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxProfilesBody))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("list kiro profiles returned HTTP %d", resp.StatusCode)
		}
		var res struct {
			Profiles []struct {
				ARN         string `json:"arn"`
				ProfileName string `json:"profileName"`
			} `json:"profiles"`
			NextToken string `json:"nextToken"`
		}
		if err := json.Unmarshal(data, &res); err != nil {
			return nil, fmt.Errorf("malformed kiro profile list: %w", err)
		}
		for _, p := range res.Profiles {
			if ARNRegion(p.ARN) == "" {
				continue
			}
			out = append(out, Profile{ARN: p.ARN, Name: printable(p.ProfileName, 64)})
			if len(out) >= maxProfiles {
				return out, nil
			}
		}
		if res.NextToken == "" {
			break
		}
		next = res.NextToken
	}
	return out, nil
}

// WithProfile records p in the login: its ARN, and its region as the Kiro API
// region.
func (l Login) WithProfile(p Profile) Login {
	l.ProfileARN = p.ARN
	if r := p.Region(); r != "" {
		l.APIRegion = r
	}
	return l
}

// printable keeps a service-supplied label to printable runes, capped.
func printable(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r >= 0x200e && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		b.WriteRune(r)
		n++
		if n >= max {
			break
		}
	}
	return b.String()
}

// ProfileRegions are the regions Kiro is known to serve profiles from. The
// login's own API and SSO regions are always tried first.
var ProfileRegions = []string{"us-east-1", "eu-central-1"}

func profileRegionsFor(login Login) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range append([]string{login.APIRegion, login.Region}, ProfileRegions...) {
		if r != "" && ValidRegion(r) && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// Endpoints overrides the hosts ResolveProfile talks to, for tests. Empty
// fields mean the real AWS hosts for the login's regions.
type Endpoints struct {
	OIDC     string
	Profiles []string
}

// ResolveProfile settles the login's profile after a sign-in.
//
// An explicit ARN wins and is only validated. A login that already names a
// profile (an import) keeps it. Otherwise the account's profiles are listed:
// with one, it is adopted; with none (a Builder ID account may have none) the
// login is returned unchanged; with several, they are returned for the caller to
// choose from with Login.WithProfile.
//
// Listing mints a token, so the returned login carries whatever refresh token
// is current afterwards: it is the one to store.
func ResolveProfile(ctx context.Context, client *http.Client, login Login, explicitARN string, ep Endpoints) (Login, []Profile, error) {
	if explicitARN = strings.TrimSpace(explicitARN); explicitARN != "" {
		p := Profile{ARN: explicitARN}
		if p.Region() == "" {
			return login, nil, fmt.Errorf("%q is not a CodeWhisperer profile ARN", explicitARN)
		}
		return login.WithProfile(p), nil, nil
	}
	if p := (Profile{ARN: login.ProfileARN}); login.ProfileARN != "" && p.Region() != "" {
		return login.WithProfile(p), nil, nil
	}
	token, current, err := Mint(ctx, client, login, ep.OIDC)
	login = current
	if err != nil {
		return login, nil, err
	}
	var groups [][]string
	if ep.Profiles == nil {
		for _, region := range profileRegionsFor(login) {
			groups = append(groups, []string{ProfilesBaseURL(region), APIBaseURL(region)})
		}
	} else {
		for _, b := range ep.Profiles {
			groups = append(groups, []string{b})
		}
	}
	var out []Profile
	seen := map[string]bool{}
	var lastErr error
	ok := false
	for _, group := range groups {
		for _, base := range group {
			ps, err := ListProfiles(ctx, client, base, token)
			if err != nil {
				lastErr = err
				continue
			}
			ok = true
			for _, p := range ps {
				if !seen[p.ARN] {
					seen[p.ARN] = true
					out = append(out, p)
				}
			}
			break
		}
	}
	if !ok {
		return login, nil, lastErr
	}
	switch len(out) {
	case 0:
		return login, nil, nil
	case 1:
		return login.WithProfile(out[0]), nil, nil
	}
	return login, out, nil
}
