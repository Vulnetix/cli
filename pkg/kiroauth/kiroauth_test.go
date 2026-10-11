package kiroauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAWS is the SSO-OIDC endpoint and the CodeWhisperer profile listing.
type fakeAWS struct {
	polls    atomic.Int32
	pending  int32 // polls answered authorization_pending before approval
	profiles string
	rotate   bool
}

func (f *fakeAWS) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/client/register", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["clientName"] != ClientName {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"clientId": "cid", "clientSecret": "csecret", "clientSecretExpiresAt": time.Now().Add(90 * 24 * time.Hour).Unix()})
	})
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deviceCode": "dev-code", "userCode": "ABCD-EFGH",
			"verificationUri": "https://device.sso.us-east-1.amazonaws.com/", "verificationUriComplete": "https://device.sso.us-east-1.amazonaws.com/?user_code=ABCD-EFGH",
			"expiresIn": 60, "interval": 0,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in["grantType"] {
		case "urn:ietf:params:oauth:grant-type:device_code":
			if f.polls.Add(1) <= f.pending {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "at", "refreshToken": "rt-device", "expiresIn": 3600})
		case "refresh_token":
			out := map[string]any{"accessToken": "at-refreshed", "expiresIn": 3600}
			if f.rotate {
				out["refreshToken"] = "rt-rotated"
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "AmazonCodeWhispererService.ListAvailableProfiles" || r.Header.Get("Authorization") != "Bearer at-refreshed" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(f.profiles))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDeviceLogin(t *testing.T) {
	f := &fakeAWS{pending: 2}
	srv := f.server(t)
	d := DeviceLogin{BaseURL: srv.URL, PollInterval: 10 * time.Millisecond, SlowDown: time.Millisecond}
	g, err := d.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g.UserCode != "ABCD-EFGH" || !strings.Contains(g.BrowseURL(), "user_code") {
		t.Fatalf("grant = %v", g)
	}
	if strings.Contains(g.String(), "dev-code") || strings.Contains(g.String(), "csecret") {
		t.Fatal("a grant renders a secret")
	}
	l, err := d.Poll(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if l.RefreshToken != "rt-device" || l.ClientID != "cid" || l.StartURL != BuilderIDStartURL || l.Region != DefaultRegion {
		t.Fatalf("login = %v", l)
	}
	if f.polls.Load() != 3 {
		t.Fatalf("polls = %d", f.polls.Load())
	}
	back, err := ParseLogin(l.Encode())
	if err != nil || back != l {
		t.Fatalf("round trip: %v", err)
	}
}

func TestDeviceLoginRefusesBadSettings(t *testing.T) {
	for _, d := range []DeviceLogin{
		{StartURL: "http://insecure.example.com/start"},
		{Region: "not a region"},
		{APIRegion: "us-east-1.evil"},
		{BaseURL: "https://evil.example.com"},
	} {
		if _, err := d.Start(context.Background()); err == nil {
			t.Errorf("%+v: accepted", d)
		}
	}
}

func testLogin() Login {
	return Login{RefreshToken: "rt", ClientID: "cid", ClientSecret: "csecret", Region: "us-east-1"}
}

func TestResolveProfile(t *testing.T) {
	two := `{"profiles":[{"arn":"arn:aws:codewhisperer:eu-central-1:111111111111:profile/A","profileName":"A"},{"arn":"arn:aws:codewhisperer:us-east-1:111111111111:profile/B","profileName":"B‮"}]}`
	one := `{"profiles":[{"arn":"arn:aws:codewhisperer:eu-central-1:111111111111:profile/A","profileName":"A"}]}`

	f := &fakeAWS{profiles: one, rotate: true}
	srv := f.server(t)
	ep := Endpoints{OIDC: srv.URL, Profiles: []string{srv.URL}}
	l, choices, err := ResolveProfile(context.Background(), nil, testLogin(), "", ep)
	if err != nil || choices != nil {
		t.Fatalf("%v %v", err, choices)
	}
	if l.ProfileARN != "arn:aws:codewhisperer:eu-central-1:111111111111:profile/A" || l.APIRegion != "eu-central-1" {
		t.Fatalf("one profile is adopted: %v", l)
	}
	if l.RefreshToken != "rt-rotated" {
		t.Fatal("the login to store must carry the rotated refresh token")
	}

	f.profiles = two
	_, choices, err = ResolveProfile(context.Background(), nil, testLogin(), "", ep)
	if err != nil || len(choices) != 2 || strings.ContainsRune(choices[1].Name, '‮') {
		t.Fatalf("several profiles are offered, cleaned: %v %v", err, choices)
	}

	l, _, err = ResolveProfile(context.Background(), nil, testLogin(), "arn:aws:codewhisperer:ap-southeast-2:1:profile/X", ep)
	if err != nil || l.APIRegion != "ap-southeast-2" {
		t.Fatalf("an explicit ARN wins: %v %v", err, l)
	}
	if _, _, err := ResolveProfile(context.Background(), nil, testLogin(), "arn:aws:s3:::bucket", ep); err == nil {
		t.Fatal("a non-CodeWhisperer ARN is refused")
	}
}

func TestMintRelogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	if _, _, err := Mint(context.Background(), nil, testLogin(), srv.URL); !errors.Is(err, ErrReloginRequired) {
		t.Fatalf("err = %v", err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestImportIDECache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "")
	writeFile(t, CachePath(home), `{"refreshToken":"rt-ide","authMethod":"IdC","provider":"Enterprise","region":"eu-central-1","clientIdHash":"abc123","startUrl":"https://corp.awsapps.com/start","profileArn":"arn:aws:codewhisperer:eu-central-1:1:profile/P"}`)
	writeFile(t, filepath.Join(filepath.Dir(CachePath(home)), "abc123.json"), `{"clientId":"cid","clientSecret":"csecret","expiresAt":"2030-01-01T00:00:00Z"}`)
	l, src, err := Import(home)
	if err != nil {
		t.Fatal(err)
	}
	if src != CachePath(home) || l.RefreshToken != "rt-ide" || l.Region != "eu-central-1" || l.ClientSecretExpiresAt == 0 || l.ProfileARN == "" {
		t.Fatalf("login = %v from %s", l, src)
	}

	writeFile(t, CachePath(home), `{"refreshToken":"rt","authMethod":"social","provider":"Github"}`)
	if _, _, err := Import(home); !errors.Is(err, ErrSocialLogin) {
		t.Fatalf("social login: %v", err)
	}
	writeFile(t, CachePath(home), `{"refreshToken":"rt","clientIdHash":"../../etc/passwd"}`)
	if _, _, err := Import(home); err == nil {
		t.Fatal("a client hash that is a path was followed")
	}
}

func TestImportKiroCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", "")
	db := CLIDatabasePaths(home)[0]
	writeFile(t, db, "not really sqlite")
	defer func(orig func(string, string) ([]byte, error)) { sqliteQuery = orig }(sqliteQuery)
	sqliteQuery = func(_, query string) ([]byte, error) {
		if strings.Contains(query, "FROM state") {
			return []byte(`[{"key":"api.codewhisperer.profile","value":"{\"arn\":\"arn:aws:codewhisperer:us-east-1:1:profile/CLI\"}"}]`), nil
		}
		return []byte(`[{"key":"kirocli:odic:token","value":"{\"refresh_token\":\"rt-cli\",\"region\":\"us-east-1\"}"},` +
			`{"key":"kirocli:odic:device-registration","value":"{\"client_id\":\"cid\",\"client_secret\":\"csecret\",\"client_secret_expires_at\":1900000000}"}]`), nil
	}
	l, src, err := Import(home)
	if err != nil {
		t.Fatal(err)
	}
	if src != db || l.RefreshToken != "rt-cli" || l.ClientSecretExpiresAt != 1900000000 || !strings.HasSuffix(l.ProfileARN, "/CLI") {
		t.Fatalf("login = %v from %s", l, src)
	}
}

func TestImportNothing(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	if _, _, err := Import(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}
