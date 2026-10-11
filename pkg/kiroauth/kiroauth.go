// Package kiroauth signs in to Kiro with an AWS Builder ID or an IAM Identity
// Center start URL and produces the Kiro login the Vulnetix AI Firewall stores
// in the secrets vault for the kiro provider.
//
// Kiro has no API key. A login is an AWS SSO-OIDC refresh token plus the client
// registration that minted it; the gateway trades it for a short-lived access
// token before each request. This package runs the device authorization grant
// itself (register a public client, start the device authorization, poll the
// token endpoint), or imports the sign-in Kiro's IDE or kiro-cli already holds.
//
// The login's JSON shape is shared with belai (belai/internal/kiroauth), the
// vault (vdb-site handler/vault_kiro.go) and the gateway
// (ai-firewall/internal/kiroauth); the four must not drift.
//
// Every token goes only to a pinned host: oidc.<region>.amazonaws.com and
// q.<region>.amazonaws.com or codewhisperer.<region>.amazonaws.com, over https
// and without redirects. The device code, client secret, refresh and access
// tokens are never rendered.
package kiroauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Defaults for an AWS Builder ID login.
const (
	BuilderIDStartURL = "https://view.awsapps.com/start"
	DefaultRegion     = "us-east-1"
)

// ClientName is the name the SSO-OIDC client registers under. The firewall gets
// its own registration, and so its own refresh token, rather than sharing the
// IDE's: a refresh token AWS rotates for one holder then never breaks the other.
const ClientName = "vulnetix-ai-firewall"

// Scopes are the CodeWhisperer scopes Kiro requests.
var Scopes = []string{
	"codewhisperer:completions",
	"codewhisperer:analysis",
	"codewhisperer:conversations",
}

// Login is everything needed to mint Kiro access tokens. It is secret as a
// whole: the refresh token and client secret are inside it.
type Login struct {
	RefreshToken          string `json:"refresh_token"`
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
	// Region is the SSO-OIDC region the login was made in.
	Region string `json:"region"`
	// StartURL is the Builder ID or IAM Identity Center start URL.
	StartURL string `json:"start_url,omitempty"`
	// APIRegion is the Kiro API region; empty means Region.
	APIRegion string `json:"api_region,omitempty"`
	// ProfileARN is the CodeWhisperer profile an Identity Center login sends
	// with each request. A Builder ID login has none.
	ProfileARN string `json:"profile_arn,omitempty"`
}

// Encode renders the login as the vault value.
func (l Login) Encode() string {
	b, _ := json.Marshal(l)
	return string(b)
}

// String never reveals the secrets.
func (l Login) String() string {
	return fmt.Sprintf("kiroauth.Login{Region:%q, StartURL:%q, APIRegion:%q, ProfileARN:%q}", l.Region, l.StartURL, l.APIRegion, l.ProfileARN)
}

// GoString never reveals the secrets.
func (l Login) GoString() string { return l.String() }

// ParseLogin decodes and validates a login.
func ParseLogin(s string) (Login, error) {
	var l Login
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &l); err != nil {
		return Login{}, errors.New("kiro login is not valid JSON")
	}
	if l.RefreshToken == "" || l.ClientID == "" || l.ClientSecret == "" {
		return Login{}, errors.New("kiro login is incomplete")
	}
	if l.Region == "" {
		l.Region = DefaultRegion
	}
	if !ValidRegion(l.Region) {
		return Login{}, fmt.Errorf("kiro login has an invalid region %q", l.Region)
	}
	if l.APIRegion != "" && !ValidRegion(l.APIRegion) {
		return Login{}, fmt.Errorf("kiro login has an invalid api region %q", l.APIRegion)
	}
	return l, nil
}

// APIRegionOrDefault returns the Kiro API region: the explicit or
// profile-derived API region, else the SSO region, else us-east-1.
func (l Login) APIRegionOrDefault() string {
	for _, r := range []string{l.APIRegion, l.Region} {
		if r != "" && ValidRegion(r) {
			return r
		}
	}
	return DefaultRegion
}

// Expired reports whether the client registration has expired.
func (l Login) Expired(now time.Time) bool {
	return l.ClientSecretExpiresAt > 0 && now.Unix() >= l.ClientSecretExpiresAt
}

var regionRE = regexp.MustCompile(`^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-[0-9]{1,2}$`)

// ValidRegion reports whether r looks like an AWS region name.
func ValidRegion(r string) bool { return regionRE.MatchString(r) }

// OIDCBaseURL is the SSO-OIDC endpoint for region.
func OIDCBaseURL(region string) string {
	return "https://oidc." + region + ".amazonaws.com"
}

// APIBaseURL is the Kiro API endpoint for region.
func APIBaseURL(region string) string {
	if !ValidRegion(region) {
		region = DefaultRegion
	}
	return "https://q." + region + ".amazonaws.com"
}

var apiHostRE = regexp.MustCompile(`^(q|codewhisperer)\.[a-z0-9-]+\.amazonaws\.com$`)
var oidcHostRE = regexp.MustCompile(`^oidc\.[a-z0-9-]+\.amazonaws\.com$`)

// AllowedAPIURL reports whether an access token may be sent to base: an https
// Kiro API host, or a loopback origin (tests).
func AllowedAPIURL(base string) bool { return allowedURL(base, apiHostRE) }

// AllowedOIDCURL is AllowedAPIURL for the SSO-OIDC endpoint.
func AllowedOIDCURL(base string) bool { return allowedURL(base, oidcHostRE) }

func allowedURL(base string, host *regexp.Regexp) bool {
	u, err := url.Parse(base)
	if err != nil || u.User != nil {
		return false
	}
	h := u.Hostname()
	if isLoopback(h) {
		return u.Scheme == "http" || u.Scheme == "https"
	}
	return u.Scheme == "https" && u.Port() == "" && host.MatchString(h)
}

func isLoopback(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ValidStartURL reports whether s is an acceptable start URL: https with a
// host and no credentials.
func ValidStartURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}
