package aifirewall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ServesFirewall decides which vault entries the gateway may use: an entry is
// live only when it is not revoked and carries an allow grant for the firewall
// surface.
func TestVaultEntryServesFirewall(t *testing.T) {
	allow := VaultGrant{Surface: VaultSurfaceFirewall, Effect: "allow"}
	tests := []struct {
		name string
		e    VaultEntry
		want bool
	}{
		{
			name: "granted and live",
			e:    VaultEntry{State: "active", Grants: []VaultGrant{allow}},
			want: true,
		},
		{
			name: "revoked even when granted",
			e:    VaultEntry{State: "revoked", Grants: []VaultGrant{allow}},
			want: false,
		},
		{
			name: "no grants",
			e:    VaultEntry{State: "active"},
			want: false,
		},
		{
			name: "grant for another surface",
			e:    VaultEntry{State: "active", Grants: []VaultGrant{{Surface: "ci", Effect: "allow"}}},
			want: false,
		},
		{
			name: "deny grant for the firewall surface",
			e:    VaultEntry{State: "active", Grants: []VaultGrant{{Surface: VaultSurfaceFirewall, Effect: "deny"}}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.ServesFirewall(); got != tt.want {
				t.Errorf("ServesFirewall = %v, want %v", got, tt.want)
			}
		})
	}
}

func newVaultServer(t *testing.T, handler http.HandlerFunc) (VaultClient, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return VaultClient{BaseURL: srv.URL, Authorization: "ApiKey " + testKey, HTTP: srv.Client()}, &calls
}

func TestVaultEntries(t *testing.T) {
	client, calls := newVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiKey "+testKey {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"entries":[{"id":"e1","provider":"openai","state":"active"}]}`))
	})

	entries, err := client.Entries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "e1" {
		t.Fatalf("entries = %+v", entries)
	}
	if len(*calls) != 1 || (*calls)[0] != "GET /api/site/v1/vault" {
		t.Errorf("calls = %v", *calls)
	}
}

func TestVaultEntriesRefusesErrorPayload(t *testing.T) {
	client, _ := newVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"nope"}`))
	})
	if _, err := client.Entries(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestVaultEntriesRejectsRedirect(t *testing.T) {
	var client VaultClient
	handling := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}
	client, _ = newVaultServer(t, handling)
	if _, err := client.Entries(context.Background()); err == nil {
		t.Fatal("a redirect carrying a credential must be an error, not a hop")
	}
}

func TestVaultEntriesMalformedJSON(t *testing.T) {
	client, _ := newVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})
	if _, err := client.Entries(context.Background()); err == nil {
		t.Fatal("expected malformed response error")
	}
}

func TestVaultCreateAndReplace(t *testing.T) {
	client, calls := newVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		var seen map[string]any
		_ = json.NewDecoder(r.Body).Decode(&seen)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			if seen["provider"] != "openai" || seen["kind"] != VaultKindProvider {
				t.Errorf("create body = %v", seen)
			}
			_, _ = w.Write([]byte(`{"entry":{"id":"e1"}}`))
			return
		}
		if seen["value"] != "vlx_new" {
			t.Errorf("replace body = %v", seen)
		}
		_, _ = w.Write([]byte(`{"entry":{"id":"e1","version":2}}`))
	})

	entry, err := client.Create(context.Background(), VaultSave{
		Kind: VaultKindProvider, Provider: "openai", Name: "n", Value: "vlx_new",
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID != "e1" {
		t.Errorf("create entry = %+v", entry)
	}

	entry, err = client.Replace(context.Background(), "e1", "vlx_new")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Version != 2 {
		t.Errorf("replace entry = %+v", entry)
	}
	want := []string{"POST /api/site/v1/vault/entries", "PATCH /api/site/v1/vault/entries/e1"}
	if len(*calls) != len(want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
	for i := range want {
		if (*calls)[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, (*calls)[i], want[i])
		}
	}
}
