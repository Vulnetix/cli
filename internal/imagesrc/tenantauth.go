package imagesrc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// Registry credentials for an authenticated run.
//
// A run that is signed in to Vulnetix can read a private image with the
// organisation's own registry connection (the Registries page in Resolve, or
// a RegistryConnection document). The CLI never holds that login: it asks
// Vulnetix for a pull token for the one repository it is about to read, which
// the registry itself expires within minutes, and presents it as a bearer token.
// Vulnetix answers only for a registry host and repository that the signed in
// organisation has connected, and never hands out a long-lived login; a registry
// that has no token service gets ErrNoEphemeral and the run uses the machine's
// own docker credentials instead, as it always did.
//
// Anything else that goes wrong asking (offline, a plan without registry
// credentials, a connection the registry refuses) falls back the same way, so
// the feature can only add access, never remove it. Community runs and
// `--no-upload` runs do not ask at all: nothing about the image is sent to
// Vulnetix by them.

// TenantToken is a short-lived pull token for one repository.
type TenantToken struct {
	Token string
	// ExpiresAt is when the registry stops accepting it. Zero means unknown, and
	// is treated as about to expire.
	ExpiresAt time.Time
}

// Errors a TokenSource reports. Everything else is an unexpected failure.
var (
	// ErrNoConnection means the organisation has not connected this registry host
	// and repository (or the plan has no registry credentials, or the caller may
	// not use them): there is nothing to add to the user's own credentials.
	ErrNoConnection = errors.New("no registry connection for this repository")
	// ErrNoEphemeral means there is a connection but the registry has no token
	// service, so no short-lived credential can be issued for it.
	ErrNoEphemeral = errors.New("the registry cannot issue a short-lived credential")
)

// TokenSource asks Vulnetix for a pull token for registry (a host with an
// optional port) and repository (the path in it, such as acme/api).
type TokenSource interface {
	OCIToken(ctx context.Context, registry, repository string) (*TenantToken, error)
}

// tenantKeychain resolves registry credentials: the organisation's connection
// first, then the fallback (the user's docker configuration and credential
// helpers).
type tenantKeychain struct {
	ctx      context.Context
	source   TokenSource
	fallback authn.Keychain
	warn     func(string)
}

// Resolve implements authn.Keychain. It does no network I/O: the token is asked
// for when the transport first needs a credential, so a registry that allows
// anonymous reads costs nothing.
func (k *tenantKeychain) Resolve(res authn.Resource) (authn.Authenticator, error) {
	repo, ok := res.(name.Repository)
	if !ok {
		return k.fallback.Resolve(res)
	}
	return &tenantAuth{
		ctx: k.ctx, source: k.source, fallback: k.fallback, warn: k.warn,
		resource: res, registry: repo.RegistryStr(), repository: repo.RepositoryStr(),
	}, nil
}

// tenantAuth is the authenticator of one repository.
type tenantAuth struct {
	ctx        context.Context
	source     TokenSource
	fallback   authn.Keychain
	warn       func(string)
	resource   authn.Resource
	registry   string
	repository string

	mu    sync.Mutex
	tok   *TenantToken
	asked bool // the source said no, or failed: use the fallback from now on
}

// refreshMargin is how long before expiry a token is replaced.
const refreshMargin = 20 * time.Second

// Authorization implements authn.Authenticator.
func (a *tenantAuth) Authorization() (*authn.AuthConfig, error) {
	return a.AuthorizationContext(a.ctx)
}

// AuthorizationContext implements authn.ContextAuthenticator. The transport
// calls it whenever it needs a credential, including after the registry has
// expired the last token, so a long pull gets a fresh token when it needs one.
func (a *tenantAuth) AuthorizationContext(ctx context.Context) (*authn.AuthConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok != nil && a.tok.Token != "" && time.Until(a.tok.ExpiresAt) > refreshMargin {
		return &authn.AuthConfig{RegistryToken: a.tok.Token}, nil
	}
	if !a.asked || a.tok != nil {
		tok, err := a.source.OCIToken(ctx, a.registry, a.repository)
		switch {
		case err == nil && tok != nil && tok.Token != "":
			a.tok = tok
			return &authn.AuthConfig{RegistryToken: tok.Token}, nil
		case errors.Is(err, ErrNoConnection):
			// Nothing connected for this repository: the common case, silent.
		case errors.Is(err, ErrNoEphemeral):
			a.say("Vulnetix holds a login for " + a.registry + " but the registry has no token service, so it cannot be used from here; using your own docker credentials")
		case err != nil:
			// err is built from the HTTP status and a code, never a credential.
			a.say(fmt.Sprintf("could not get a registry token for %s from Vulnetix (%v); using your own docker credentials", a.registry, err))
		}
		a.tok, a.asked = nil, true
	}
	fb, err := a.fallback.Resolve(a.resource)
	if err != nil {
		return nil, err
	}
	return authn.Authorization(ctx, fb)
}

func (a *tenantAuth) say(msg string) {
	if a.warn != nil {
		a.warn(msg)
	}
}

// keychainFor is the keychain a registry read uses: the organisation's
// connection when the run is set up for it, else the user's docker
// configuration and credential helpers alone.
func keychainFor(ctx context.Context, opts Options) authn.Keychain {
	if opts.Tenant == nil {
		return authn.DefaultKeychain
	}
	return &tenantKeychain{ctx: ctx, source: opts.Tenant, fallback: authn.DefaultKeychain, warn: opts.Warn}
}
