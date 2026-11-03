package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vulnetix/cli/v4/pkg/auth"
)

// addonStatus is what the console says about the caller's Package Firewall
// add-on. The zero value means "not known": offline, no credential, an older
// site, or any failure. Unknown is not "not entitled": callers print nothing.
type addonStatus struct {
	Known bool
	// Enforced is the site's ADDON_GATING switch. With it off nothing needs the
	// add-on, so nobody is told to buy it.
	Enforced bool
	// Entitled is whether the org holds Package Firewall (a live subscription,
	// a staff grant, or Enterprise).
	Entitled bool
}

// fetchAddonStatus reads GET <siteBase>/billing/addons with the caller's
// Authorization header. Any failure, including a timeout, a non-200 answer and
// a body without the packageFirewall entry, returns the zero value.
func fetchAddonStatus(ctx context.Context, siteBase, authHeader string, timeout time.Duration) addonStatus {
	if strings.TrimSpace(authHeader) == "" {
		return addonStatus{}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(siteBase, "/")+"/billing/addons", nil)
	if err != nil {
		return addonStatus{}
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vulnetix-cli/"+version)
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return addonStatus{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return addonStatus{}
	}
	var body struct {
		Enforced        bool `json:"enforced"`
		PackageFirewall *struct {
			Entitled bool `json:"entitled"`
		} `json:"packageFirewall"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil || body.PackageFirewall == nil {
		return addonStatus{}
	}
	return addonStatus{Known: true, Enforced: body.Enforced, Entitled: body.PackageFirewall.Entitled}
}

// liveAddonStatus asks the console for the credential's add-on state. It
// returns the zero value without a credential.
func liveAddonStatus(creds *auth.Credentials) addonStatus {
	if creds == nil {
		return addonStatus{}
	}
	return fetchAddonStatus(context.Background(), siteBase(), auth.GetAuthHeader(creds), 3*time.Second)
}
