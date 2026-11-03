package imagesrc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	tenantTok  = "tenant-short-lived-token"
	dockerUser = "dockeruser"
	dockerPass = "docker-password-xyz"
)

// authRegistry is an in-memory registry that wants a login: a bearer token
// (tenantTok or the one its own token endpoint issues for the docker login).
type authRegistry struct {
	srv  *httptest.Server
	host string
	mu   sync.Mutex
	auth []string // Authorization header of each registry request
}

func newAuthRegistry(t *testing.T) *authRegistry {
	t.Helper()
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	a := &authRegistry{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			u, p, ok := r.BasicAuth()
			if !ok || u != dockerUser || p != dockerPass {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "docker-issued-token", "expires_in": 300})
			return
		}
		h := r.Header.Get("Authorization")
		a.mu.Lock()
		a.auth = append(a.auth, h)
		a.mu.Unlock()
		if h != "Bearer "+tenantTok && h != "Bearer docker-issued-token" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="http://%s/token",service="test"`, r.Host))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(a.srv.Close)
	a.host = strings.TrimPrefix(a.srv.URL, "http://")
	// Seed an image through the same storage, with the login the registry wants.
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := name.ParseReference(a.host + "/acme/api:1")
	if err := remote.Write(ref, img, remote.WithAuth(&authn.Bearer{Token: tenantTok})); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.auth = nil
	a.mu.Unlock()
	return a
}

func (a *authRegistry) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auth...)
}

type fakeSource struct {
	mu    sync.Mutex
	calls [][2]string
	tok   *TenantToken
	err   error
}

func (f *fakeSource) OCIToken(_ context.Context, registry, repository string) (*TenantToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, [2]string{registry, repository})
	return f.tok, f.err
}

// dockerConfig points the default keychain at a config with the docker login for host.
func dockerConfig(t *testing.T, host string) {
	t.Helper()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, base64.StdEncoding.EncodeToString([]byte(dockerUser+":"+dockerPass)))
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
}

func emptyDockerConfig(t *testing.T) {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir())
}

func open(t *testing.T, ref string, opts Options) (*Image, []string) {
	t.Helper()
	var notes []string
	opts.Source = SourceRegistry
	opts.Warn = func(m string) { notes = append(notes, m) }
	img, err := Open(context.Background(), ref, opts)
	if err != nil {
		t.Fatalf("open: %v (notes %v)", err, notes)
	}
	t.Cleanup(img.Close)
	return img, notes
}

func TestTenantTokenIsPresentedAsABearerToken(t *testing.T) {
	reg := newAuthRegistry(t)
	emptyDockerConfig(t)
	src := &fakeSource{tok: &TenantToken{Token: tenantTok, ExpiresAt: time.Now().Add(5 * time.Minute)}}
	img, notes := open(t, reg.host+"/acme/api:1", Options{Tenant: src})
	if img.Meta.Digest == "" || len(notes) != 0 {
		t.Fatalf("digest %q notes %v", img.Meta.Digest, notes)
	}
	if len(src.calls) == 0 || src.calls[0] != [2]string{reg.host, "acme/api"} {
		t.Fatalf("the source was asked %v", src.calls)
	}
	// The ping that finds the challenge carries no login; every request after it
	// carries the tenant token and nothing else.
	authed := 0
	for _, h := range reg.seen() {
		if h == "" {
			continue
		}
		authed++
		if h != "Bearer "+tenantTok {
			t.Fatalf("the registry saw %q", h)
		}
	}
	if authed == 0 {
		t.Fatal("no request carried the tenant token")
	}
}

// With nothing connected the run is the one it always was: the user's docker login.
func TestNoConnectionFallsBackToDockerCredentialsSilently(t *testing.T) {
	reg := newAuthRegistry(t)
	dockerConfig(t, reg.host)
	src := &fakeSource{err: ErrNoConnection}
	_, notes := open(t, reg.host+"/acme/api:1", Options{Tenant: src})
	if len(notes) != 0 {
		t.Fatalf("the common case says nothing: %v", notes)
	}
	if !contains(reg.seen(), "Bearer docker-issued-token") {
		t.Fatalf("the docker login was not used: %v", reg.seen())
	}
	if len(src.calls) != 1 {
		t.Fatalf("one ask per repository, not one per request: %v", src.calls)
	}
}

func TestNoTokenServiceSaysSoAndFallsBack(t *testing.T) {
	reg := newAuthRegistry(t)
	dockerConfig(t, reg.host)
	_, notes := open(t, reg.host+"/acme/api:1", Options{Tenant: &fakeSource{err: ErrNoEphemeral}})
	if len(notes) != 1 || !strings.Contains(notes[0], reg.host) || !strings.Contains(notes[0], "no token service") {
		t.Fatalf("notes = %v", notes)
	}
}

func TestAnUnexpectedFailureFallsBackWithANoteThatHoldsNoCredential(t *testing.T) {
	reg := newAuthRegistry(t)
	dockerConfig(t, reg.host)
	_, notes := open(t, reg.host+"/acme/api:1", Options{Tenant: &fakeSource{err: errors.New("HTTP 502 registry_refused: the registry did not issue a token for this repository")}})
	if len(notes) != 1 || !strings.Contains(notes[0], "HTTP 502") || strings.Contains(strings.Join(notes, " "), dockerPass) {
		t.Fatalf("notes = %v", notes)
	}
}

// Without a tenant source nothing is asked and nothing changes.
func TestNoTenantSourceUsesDockerCredentialsOnly(t *testing.T) {
	reg := newAuthRegistry(t)
	dockerConfig(t, reg.host)
	if _, notes := open(t, reg.host+"/acme/api:1", Options{}); len(notes) != 0 {
		t.Fatalf("notes = %v", notes)
	}
	if contains(reg.seen(), "Bearer "+tenantTok) {
		t.Fatal("no tenant token without a tenant source")
	}
}

// A registry that does not need a login is read anonymously. The connection is
// asked about once for the repository (the transport cannot tell before it asks),
// and a no ends it.
func TestPublicRegistryNeedsNoCredential(t *testing.T) {
	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(inner)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	img, _ := random.Image(256, 1)
	ref, _ := name.ParseReference(host + "/pub/app:1")
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	emptyDockerConfig(t)
	src := &fakeSource{err: ErrNoConnection}
	if got, _ := open(t, host+"/pub/app:1", Options{Tenant: src}); got.Meta.Digest == "" {
		t.Fatal("no digest")
	}
	if len(src.calls) > 1 {
		t.Fatalf("an anonymous registry is asked at most once: %v", src.calls)
	}
}

// The token is replaced shortly before it expires, and not before.
func TestTokenIsRefreshedBeforeItExpires(t *testing.T) {
	src := &fakeSource{tok: &TenantToken{Token: "t1", ExpiresAt: time.Now().Add(5 * time.Minute)}}
	repo, _ := name.NewRepository("registry.example.com/acme/api")
	k := &tenantKeychain{ctx: context.Background(), source: src, fallback: authn.DefaultKeychain}
	a, err := k.Resolve(repo)
	if err != nil {
		t.Fatal(err)
	}
	get := func() string {
		c, err := authn.Authorization(context.Background(), a)
		if err != nil {
			t.Fatal(err)
		}
		return c.RegistryToken
	}
	first, second := get(), get() // two reads, one fetch: the token is reused
	if first != "t1" || second != "t1" || len(src.calls) != 1 {
		t.Fatalf("a fresh token is reused: %v", src.calls)
	}
	src.mu.Lock()
	src.tok = &TenantToken{Token: "t2", ExpiresAt: time.Now().Add(5 * time.Minute)}
	a.(*tenantAuth).tok.ExpiresAt = time.Now().Add(5 * time.Second) // inside the margin
	src.mu.Unlock()
	if got := get(); got != "t2" || len(src.calls) != 2 {
		t.Fatalf("an expiring token is replaced: %q %v", got, src.calls)
	}
}

// A token the source can no longer issue ends the use of the connection for
// this repository: from then on the user's credentials answer.
func TestLosingTheConnectionMidPullFallsBack(t *testing.T) {
	emptyDockerConfig(t)
	src := &fakeSource{tok: &TenantToken{Token: "t1", ExpiresAt: time.Now().Add(time.Second)}}
	repo, _ := name.NewRepository("registry.example.com/acme/api")
	k := &tenantKeychain{ctx: context.Background(), source: src, fallback: authn.DefaultKeychain}
	a, _ := k.Resolve(repo)
	if c, _ := authn.Authorization(context.Background(), a); c.RegistryToken != "t1" {
		t.Fatalf("first = %+v", c)
	}
	src.mu.Lock()
	src.tok, src.err = nil, ErrNoConnection
	src.mu.Unlock()
	c, err := authn.Authorization(context.Background(), a)
	if err != nil || c.RegistryToken != "" || c.Username != "" {
		t.Fatalf("anonymous fallback expected: %+v %v", c, err)
	}
	n := len(src.calls)
	_, _ = authn.Authorization(context.Background(), a)
	if len(src.calls) != n {
		t.Fatal("it must not ask again once it has said no")
	}
}

// Only a repository is resolved through the tenant; a bare registry is not.
func TestOnlyRepositoriesAreResolvedThroughTheTenant(t *testing.T) {
	emptyDockerConfig(t)
	src := &fakeSource{err: errors.New("must not be asked")}
	reg, _ := name.NewRegistry("registry.example.com")
	k := &tenantKeychain{ctx: context.Background(), source: src, fallback: authn.DefaultKeychain}
	a, err := k.Resolve(reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.(*tenantAuth); ok {
		t.Fatal("a registry resource has no repository to ask for")
	}
	if len(src.calls) > 1 {
		t.Fatal("asked")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
