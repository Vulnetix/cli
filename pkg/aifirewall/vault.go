package aifirewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The secrets vault holds the org's provider keys and decides which API key
// owners may use each one through the gateway. It lives on the console's site
// API, which accepts the same ApiKey credential as the VDB API.

// VaultSurfaceFirewall is the vault surface the AI firewall reads.
const VaultSurfaceFirewall = "ai_firewall"

// VaultKindProvider is a vault entry holding a provider key.
const VaultKindProvider = "provider_key"

// VaultGrant allows (or denies) a vault entry to the subjects of one surface.
type VaultGrant struct {
	Surface string   `json:"surface"`
	Effect  string   `json:"effect"`
	All     bool     `json:"all,omitempty"`
	IDs     []string `json:"ids,omitempty"`
}

// VaultEntry is the part of a vault entry view this client reads. The value is
// never returned by the vault.
type VaultEntry struct {
	ID        string       `json:"id"`
	Kind      string       `json:"kind"`
	Provider  string       `json:"provider"`
	Name      string       `json:"name"`
	Last4     string       `json:"last4"`
	Version   int          `json:"version"`
	State     string       `json:"state"`
	Grants    []VaultGrant `json:"grants"`
	ExpiresAt int64        `json:"expiresAt"`
}

// ServesFirewall reports whether the entry is live and granted to the AI
// firewall.
func (e VaultEntry) ServesFirewall() bool {
	if e.State == "revoked" {
		return false
	}
	for _, g := range e.Grants {
		if g.Surface == VaultSurfaceFirewall && g.Effect == "allow" {
			return true
		}
	}
	return false
}

// VaultSave is a new vault entry.
type VaultSave struct {
	Kind      string       `json:"kind"`
	Provider  string       `json:"provider"`
	Name      string       `json:"name"`
	Value     string       `json:"value"`
	Grants    []VaultGrant `json:"grants"`
	ExpiresAt int64        `json:"expiresAt,omitempty"`
}

// VaultClient talks to the console's secrets vault API.
type VaultClient struct {
	// BaseURL is the console origin, e.g. https://www.vulnetix.com.
	BaseURL string
	// Authorization is the request's Authorization header value.
	Authorization string
	HTTP          *http.Client
}

func (c VaultClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+"/api/site/v1/vault"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.Authorization)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	// The request carries a credential and, on a save, a secret: a redirect is
	// an error, never a hop.
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := cp.Do(req)
	if err != nil {
		return fmt.Errorf("secrets vault: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		if msg == "" {
			msg = e.Error
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("secrets vault refused the request (HTTP %d): %s", resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("secrets vault: malformed response")
	}
	return nil
}

// Entries lists the vault's entries.
func (c VaultClient) Entries(ctx context.Context) ([]VaultEntry, error) {
	var out struct {
		Entries []VaultEntry `json:"entries"`
	}
	if err := c.do(ctx, http.MethodGet, "", nil, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

// Create stores a new entry.
func (c VaultClient) Create(ctx context.Context, in VaultSave) (VaultEntry, error) {
	var out struct {
		Entry VaultEntry `json:"entry"`
	}
	err := c.do(ctx, http.MethodPost, "/entries", in, &out)
	return out.Entry, err
}

// Replace stores a new value for an entry, as its next version.
func (c VaultClient) Replace(ctx context.Context, id, value string) (VaultEntry, error) {
	var out struct {
		Entry VaultEntry `json:"entry"`
	}
	err := c.do(ctx, http.MethodPatch, "/entries/"+id, map[string]string{"value": value}, &out)
	return out.Entry, err
}
