package kiroauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	devicePollInterval = 5 * time.Second
	devicePollTimeout  = 10 * time.Minute
	deviceSlowDown     = 5 * time.Second
)

// ErrDeviceExpired means the code timed out before the user approved it.
var ErrDeviceExpired = errors.New("the sign-in code expired before it was approved")

// ErrDeviceDenied means the user refused the sign-in in the browser.
var ErrDeviceDenied = errors.New("the sign-in was denied in the browser")

// Grant is a started device sign-in. UserCode and the verification URLs are
// shown to the user; everything else is secret and never rendered.
type Grant struct {
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int

	deviceCode string
	reg        registration
	region     string
	startURL   string
	apiRegion  string
	profileARN string
}

// BrowseURL prefers the code-carrying URL so the user does not have to type.
func (g Grant) BrowseURL() string {
	if g.VerificationURIComplete != "" {
		return g.VerificationURIComplete
	}
	return g.VerificationURI
}

// String never reveals the device code or the client secret.
func (g Grant) String() string {
	return fmt.Sprintf("kiroauth.Grant{UserCode:%q, VerificationURI:%q}", g.UserCode, g.VerificationURI)
}

// GoString never reveals the device code or the client secret.
func (g Grant) GoString() string { return g.String() }

// DeviceLogin runs the device authorization grant.
type DeviceLogin struct {
	// StartURL is the Builder ID or Identity Center start URL. Empty means the
	// AWS Builder ID.
	StartURL string
	// Region is the SSO-OIDC region. Empty means us-east-1.
	Region string
	// APIRegion is the Kiro API region recorded in the login.
	APIRegion string
	// ProfileARN is recorded in the login for Identity Center accounts.
	ProfileARN string

	// BaseURL overrides the SSO-OIDC endpoint (tests); it must still pass
	// AllowedOIDCURL.
	BaseURL string
	// Client makes the requests. Nil means a client with a short timeout.
	Client *http.Client
	// PollInterval is the minimum wait between polls. Zero means 5s.
	PollInterval time.Duration
	// SlowDown is added to the poll interval on slow_down. Zero means 5s.
	SlowDown time.Duration
}

func (d DeviceLogin) oidc() oidcClient { return oidcClient{base: d.BaseURL, client: d.Client} }

func (d DeviceLogin) settings() (startURL, region string, err error) {
	startURL = strings.TrimSpace(d.StartURL)
	if startURL == "" {
		startURL = BuilderIDStartURL
	}
	if !ValidStartURL(startURL) {
		return "", "", fmt.Errorf("start URL %q must be an https URL", startURL)
	}
	region = strings.TrimSpace(d.Region)
	if region == "" {
		region = DefaultRegion
	}
	if !ValidRegion(region) {
		return "", "", fmt.Errorf("invalid AWS region %q", region)
	}
	if d.APIRegion != "" && !ValidRegion(d.APIRegion) {
		return "", "", fmt.Errorf("invalid Kiro API region %q", d.APIRegion)
	}
	return startURL, region, nil
}

// Start registers a client and begins a device authorization.
func (d DeviceLogin) Start(ctx context.Context) (Grant, error) {
	startURL, region, err := d.settings()
	if err != nil {
		return Grant{}, err
	}
	o := d.oidc()
	reg, err := o.register(ctx, region, startURL)
	if err != nil {
		return Grant{}, err
	}
	var res struct {
		DeviceCode              string `json:"deviceCode"`
		UserCode                string `json:"userCode"`
		VerificationURI         string `json:"verificationUri"`
		VerificationURIComplete string `json:"verificationUriComplete"`
		ExpiresIn               int    `json:"expiresIn"`
		Interval                int    `json:"interval"`
	}
	status, oe, err := o.post(ctx, region, "/device_authorization", map[string]string{
		"clientId":     reg.ClientID,
		"clientSecret": reg.ClientSecret,
		"startUrl":     startURL,
	}, &res)
	if err != nil {
		return Grant{}, fmt.Errorf("could not start the AWS sign-in: %w", err)
	}
	if status < 200 || status >= 300 {
		return Grant{}, fmt.Errorf("the AWS sign-in was refused (HTTP %d %s)", status, safeCode(oe.Error))
	}
	if res.DeviceCode == "" || res.UserCode == "" || res.VerificationURI == "" {
		return Grant{}, errors.New("incomplete response from the AWS sign-in service")
	}
	g := Grant{
		UserCode:                res.UserCode,
		VerificationURI:         res.VerificationURI,
		VerificationURIComplete: res.VerificationURIComplete,
		ExpiresIn:               res.ExpiresIn,
		Interval:                res.Interval,
		deviceCode:              res.DeviceCode,
		reg:                     reg,
		region:                  region,
		startURL:                startURL,
		apiRegion:               d.APIRegion,
		profileARN:              strings.TrimSpace(d.ProfileARN),
	}
	if !ValidStartURL(g.VerificationURI) || (g.VerificationURIComplete != "" && !ValidStartURL(g.VerificationURIComplete)) {
		return Grant{}, errors.New("the AWS sign-in service returned a non-https verification page")
	}
	return g, nil
}

// Poll waits for the user to approve g and returns the Login. It honours the
// service's interval, backs off on slow_down, and ends at the grant's expiry or
// ctx.
func (d DeviceLogin) Poll(ctx context.Context, g Grant) (Login, error) {
	if g.deviceCode == "" {
		return Login{}, errors.New("the sign-in was not started")
	}
	expiry := devicePollTimeout
	if g.ExpiresIn > 0 {
		expiry = time.Duration(g.ExpiresIn) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, expiry)
	defer cancel()
	interval := d.PollInterval
	if interval <= 0 {
		interval = devicePollInterval
	}
	if g.Interval > 0 && time.Duration(g.Interval)*time.Second > interval {
		interval = time.Duration(g.Interval) * time.Second
	}
	slow := d.SlowDown
	if slow <= 0 {
		slow = deviceSlowDown
	}
	o := d.oidc()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return Login{}, ErrDeviceExpired
			}
			return Login{}, ctx.Err()
		case <-timer.C:
		}
		var tok tokenResponse
		status, oe, err := o.post(ctx, g.region, "/token", map[string]string{
			"clientId":     g.reg.ClientID,
			"clientSecret": g.reg.ClientSecret,
			"grantType":    "urn:ietf:params:oauth:grant-type:device_code",
			"deviceCode":   g.deviceCode,
		}, &tok)
		if err == nil && status >= 200 && status < 300 {
			if tok.RefreshToken == "" {
				return Login{}, errors.New("the AWS sign-in service returned no refresh token")
			}
			return Login{
				RefreshToken:          tok.RefreshToken,
				ClientID:              g.reg.ClientID,
				ClientSecret:          g.reg.ClientSecret,
				ClientSecretExpiresAt: g.reg.ClientSecretExpiresAt,
				Region:                g.region,
				StartURL:              g.startURL,
				APIRegion:             g.apiRegion,
				ProfileARN:            g.profileARN,
			}, nil
		}
		switch {
		case err != nil:
			// A transport hiccup or malformed body: keep trying until expiry.
		case oe.Error == "authorization_pending", oe.Error == "AuthorizationPendingException":
		case oe.Error == "slow_down", oe.Error == "SlowDownException", status == http.StatusTooManyRequests:
			interval += slow
		case oe.Error == "expired_token", oe.Error == "ExpiredTokenException":
			return Login{}, ErrDeviceExpired
		case oe.Error == "access_denied", oe.Error == "AccessDeniedException":
			return Login{}, ErrDeviceDenied
		default:
			return Login{}, fmt.Errorf("the AWS sign-in failed (HTTP %d %s)", status, safeCode(oe.Error))
		}
		timer.Reset(interval)
	}
}
