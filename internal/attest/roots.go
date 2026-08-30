package attest

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
)

// roots.go holds the trust anchors verification uses by default.
//
// The first version of this package treated "which CA do you trust" as a
// question for the caller, and skipped chain validation when they did not
// answer it. That was wrong in the way that matters: the overwhelming majority
// of keyless signatures come from the Sigstore public-good instance, cosign
// verifies against it without being asked, and a verifier that demands a
// --trusted-root before it will check anything is not being careful — it is
// making the user do its job and calling the result honesty.
//
// So the public-good root is embedded and used by default. --trusted-root is
// what it should always have been: an override for a private Sigstore
// deployment, not a prerequisite for doing any work.
//
// The pin is deliberate. Sigstore distributes its trust root through TUF, which
// is the correct mechanism and a much larger dependency; pinning the current
// root gets the default right today, and the expiry check below makes the day
// it stops being right loud rather than silent.

//go:embed roots/sigstore-public-good.pem
var sigstorePublicGoodPEM []byte

// TrustAnchor is a named set of root certificates.
type TrustAnchor struct {
	// Name identifies the anchor in output, e.g. "Sigstore public-good".
	Name string
	// Pool is what certificates chain to.
	Pool *x509.CertPool
	// Roots are the parsed certificates, for reporting expiry.
	Roots []*x509.Certificate
}

var (
	publicGoodOnce sync.Once
	publicGood     *TrustAnchor
	publicGoodErr  error
)

// PublicGood returns the embedded Sigstore public-good trust anchor.
func PublicGood() (*TrustAnchor, error) {
	publicGoodOnce.Do(func() {
		publicGood, publicGoodErr = parseAnchor("Sigstore public-good", sigstorePublicGoodPEM)
	})
	return publicGood, publicGoodErr
}

// LoadTrustAnchor reads a PEM bundle as a trust anchor.
func LoadTrustAnchor(path string) (*TrustAnchor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseAnchor(path, data)
}

// parseAnchor builds an anchor from a PEM bundle.
//
// Every certificate in the bundle goes into the pool, intermediates included.
// Fulcio publishes its intermediate and root together, and an anchor holding
// only the root would fail to build a path for a leaf whose intermediate the
// document did not carry.
func parseAnchor(name string, data []byte) (*TrustAnchor, error) {
	pool := x509.NewCertPool()
	var roots []*x509.Certificate

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		pool.AddCert(cert)
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%s contains no certificates", name)
	}
	return &TrustAnchor{Name: name, Pool: pool, Roots: roots}, nil
}

// EarliestExpiry is when the first certificate in the anchor expires.
//
// A pinned root that has quietly expired would make every verification fail
// with an unhelpful chain error, so the expiry is surfaced as its own thing.
func (a *TrustAnchor) EarliestExpiry() (name string, notAfter string) {
	if a == nil || len(a.Roots) == 0 {
		return "", ""
	}
	earliest := a.Roots[0]
	for _, c := range a.Roots[1:] {
		if c.NotAfter.Before(earliest.NotAfter) {
			earliest = c
		}
	}
	return earliest.Subject.CommonName, earliest.NotAfter.Format("2006-01-02")
}
