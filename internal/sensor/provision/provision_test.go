package provision

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnrollMessageIsTheContractsLines(t *testing.T) {
	got := string(EnrollMessage("int-1", "k1", "", "sk", "SER123", 1762041600000, "abcd"))
	want := "vulnetix-sensor-enroll/v1\nint-1\nk1\n\nsk\nSER123\n1762041600000\nabcd"
	if got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

func TestEnrollWithMDMSignsTheBody(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.UnixMilli(1762041600123)
	now = func() time.Time { return fixed }
	defer func() { now = time.Now }()

	var body mdmEnrollBody
	var authSeen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/runtime/provisioning/enroll-mdm" || r.Method != http.MethodPost {
			http.NotFound(w, r)

			return
		}
		authSeen = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"deviceUuid":"dev-1","profile":{"uuid":"p","name":"Fleet"},
			"credential":{"scheme":"Sensor","value":"dev-1:s3cret"},"config":{"mode":"guard","protection":"hardened"},"configEtag":"e1"}`))
	}))
	defer srv.Close()

	res, err := EnrollWithMDM(context.Background(), srv.URL, priv.Seed(), "int-1", "k1", "prof", EnrollRequest{
		SensorKey: "sk", MDMDeviceID: "SER123", Hostname: "h", ComputeKind: "host", OS: "linux", Arch: "amd64", Version: "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if authSeen != "" {
		t.Fatalf("an MDM enroll sends no Authorization, sent %q", authSeen)
	}
	if body.TS != fixed.UnixMilli() || body.Profile != "prof" || body.Integration != "int-1" || body.Kid != "k1" {
		t.Fatalf("body = %+v", body)
	}
	if n, err := hex.DecodeString(body.Nonce); err != nil || len(n) != 16 {
		t.Fatalf("nonce %q is not 16 bytes of hex", body.Nonce)
	}
	sig, err := base64.StdEncoding.DecodeString(body.Signature)
	if err != nil {
		t.Fatal(err)
	}
	msg := EnrollMessage(body.Integration, body.Kid, body.Profile, body.SensorKey, body.MDMDeviceID, body.TS, body.Nonce)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature does not verify over the contract's message")
	}
	if res.DeviceUUID != "dev-1" || res.Config.Mode != "guard" || res.ConfigEtag != "e1" {
		t.Fatalf("response = %+v", res)
	}
	if h := res.StoredCredential(srv.URL).AuthHeader(); h != "Sensor dev-1:s3cret" {
		t.Fatalf("auth header = %q", h)
	}
}

func TestEnrollWithMDMRefusesABadKey(t *testing.T) {
	if _, err := EnrollWithMDM(context.Background(), "http://127.0.0.1:1", []byte("short"), "i", "k", "", EnrollRequest{}); err == nil {
		t.Fatal("a key that is not 32 bytes is refused before any request")
	}
}

func TestEnrollWithPerson(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "ApiKey alice:hmac" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"enroll as a person"}`))

			return
		}
		var in EnrollRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.SensorKey != "sk" || in.Profile != "p1" {
			t.Errorf("request = %+v", in)
		}
		if r.URL.Path != "/v1/runtime/provisioning/enroll" {
			t.Errorf("path = %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"deviceUuid":"d","profile":{"uuid":"p1","name":"Laptops"},"credential":{"scheme":"ApiKey","value":"alice:hmac"},"config":{"mode":"monitor"},"configEtag":"e"}`))
	}))
	defer srv.Close()

	res, err := EnrollWithPerson(context.Background(), srv.URL+"/", "ApiKey alice:hmac", EnrollRequest{SensorKey: "sk", Profile: "p1", MDMDeviceID: "dropped"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StoredCredential("x").AuthHeader() != "ApiKey alice:hmac" {
		t.Fatalf("user-key credential = %+v", res.Credential)
	}

	_, err = EnrollWithPerson(context.Background(), srv.URL, "ApiKey org:key", EnrollRequest{SensorKey: "sk"})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 403 || !strings.Contains(err.Error(), "enroll as a person") {
		t.Fatalf("err = %v, want the site's 403 message", err)
	}
}

func TestPollConfig(t *testing.T) {
	revoked, unauthorized := false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case revoked:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"this device was revoked; enroll it again","revoked":true}`))

			return
		case unauthorized:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"not authenticated"}`))

			return
		}
		if r.Header.Get("Authorization") != "Sensor d:s" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("sensorKey") != "" {
			t.Errorf("a Sensor credential names its device; sensorKey sent")
		}
		if r.URL.Query().Get("etag") == "e2" {
			w.WriteHeader(http.StatusNotModified)

			return
		}
		_, _ = w.Write([]byte(`{"config":{"mode":"enforce","feeds":["https://f"]},"configEtag":"e2","profile":{"uuid":"p","name":"n"}}`))
	}))
	defer srv.Close()
	auth := Credential{Scheme: "Sensor", Value: "s", DeviceUUID: "d"}.AuthHeader()

	sn, changed, err := PollConfig(context.Background(), srv.URL, auth, "e1", "")
	if err != nil || !changed || sn.Config.Mode != "enforce" || sn.ConfigEtag != "e2" || sn.Profile.Name != "n" {
		t.Fatalf("200: %+v %v %v", sn, changed, err)
	}
	if _, changed, err := PollConfig(context.Background(), srv.URL, auth, "e2", ""); err != nil || changed {
		t.Fatalf("304: changed=%v err=%v", changed, err)
	}
	unauthorized = true
	if _, _, err := PollConfig(context.Background(), srv.URL, auth, "e2", ""); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("a 401 that does not say revoked is an error to retry, got %v", err)
	}
	unauthorized, revoked = false, true
	if _, _, err := PollConfig(context.Background(), srv.URL, auth, "e2", ""); !errors.Is(err, ErrRevoked) {
		t.Fatalf("401: err = %v, want ErrRevoked", err)
	}
}

func TestUninstall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Code, SensorKey string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.SensorKey != "sk" {
			w.WriteHeader(http.StatusBadRequest)

			return
		}
		if in.Code != "good" && in.Code != "" {
			w.WriteHeader(http.StatusForbidden)

			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	if err := Uninstall(context.Background(), srv.URL, "ApiKey o:k", "good", "sk"); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(context.Background(), srv.URL, "ApiKey o:k", "bad", "sk"); !errors.Is(err, ErrUninstallRefused) {
		t.Fatalf("err = %v", err)
	}
}

func TestStoreRoundTripAndPermissions(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	s := Store{Dir: filepath.Join(t.TempDir(), "etc")}
	if _, err := s.LoadCredential(); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("err = %v", err)
	}
	c := Credential{Scheme: "Sensor", Value: "d:s", DeviceUUID: "d", Endpoint: "https://x"}
	if err := s.SaveCredential(c); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(s.CredentialPath())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %v %v", st.Mode(), err)
	}
	got, err := s.LoadCredential()
	if err != nil || got != c {
		t.Fatalf("got %+v %v", got, err)
	}

	// systemd's LoadCredential copy wins.
	credDir := t.TempDir()
	raw, _ := json.Marshal(Credential{Scheme: "ApiKey", Value: "o:k"})
	_ = os.WriteFile(filepath.Join(credDir, "credential"), raw, 0o400)
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)
	if got, _ := s.LoadCredential(); got.AuthHeader() != "ApiKey o:k" {
		t.Fatalf("CREDENTIALS_DIRECTORY not preferred: %+v", got)
	}
}

func TestLoadSnapshotPrefersTheNewer(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if _, _, err := LoadSnapshot(a, b); err == nil {
		t.Fatal("no snapshot is an error")
	}
	_ = SaveSnapshotAt(a, Snapshot{ConfigEtag: "old"})
	_ = SaveSnapshotAt(b, Snapshot{ConfigEtag: "new"})
	past := time.Now().Add(-time.Hour)
	_ = os.Chtimes(a, past, past)
	sn, path, err := LoadSnapshot(a, b)
	if err != nil || sn.ConfigEtag != "new" || path != b {
		t.Fatalf("got %+v %s %v", sn, path, err)
	}
}

func TestAuthHeader(t *testing.T) {
	cases := map[string]Credential{
		"Sensor dev:sec": {Scheme: "Sensor", Value: "dev:sec", DeviceUUID: "dev"},
		"Sensor dev:raw": {Scheme: "Sensor", Value: "raw", DeviceUUID: "dev"},
		"ApiKey org:hex": {Scheme: "ApiKey", Value: "org:hex"},
		"":               {Scheme: "Bearer", Value: "x"},
	}
	for want, c := range cases {
		if got := c.AuthHeader(); got != want {
			t.Errorf("%+v: %q, want %q", c, got, want)
		}
	}
}

func TestParseKey(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	for _, enc := range []string{base64.StdEncoding.EncodeToString(seed) + "\n", base64.RawURLEncoding.EncodeToString(seed)} {
		got, err := ParseKey([]byte(enc))
		if err != nil || len(got) != 32 || got[0] != 7 {
			t.Fatalf("%q: %v %v", enc, got, err)
		}
	}
}

func TestApiKeyDevicesNameTheirSensorKey(t *testing.T) {
	if (Credential{Scheme: "ApiKey"}).SensorKeyParam("sk") != "sk" || (Credential{Scheme: "Sensor"}).SensorKeyParam("sk") != "" {
		t.Fatal("only an ApiKey credential needs the sensor key")
	}
	var q string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.RawQuery
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	if _, changed, err := PollConfig(context.Background(), srv.URL, "ApiKey o:k", "e1", "sk"); err != nil || changed {
		t.Fatal(changed, err)
	}
	if q != "etag=e1&sensorKey=sk" {
		t.Fatalf("query = %q", q)
	}
}
