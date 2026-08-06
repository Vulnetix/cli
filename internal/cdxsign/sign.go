// Package cdxsign signs a CycloneDX document with the identity the machine
// running the scan already has.
//
// The identity is deliberately not Vulnetix's. The CLI runs on customer
// machines, so it cannot hold a Vulnetix credential, and it should not: a scan
// run in a customer's pipeline is more usefully attested by that customer than
// by the tool vendor. In GitHub Actions, GitLab CI and anywhere else that
// exposes an OIDC token, public Fulcio already accepts that identity, so the
// result verifies with stock cosign and no Vulnetix trust root.
//
// On a laptop there is no such identity, and that is not an error. Signing is
// skipped with a reason and the scan completes, because losing scan results
// over a missing signature would be a worse outcome than an unsigned document.
package cdxsign

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
)

// Result reports what signing produced.
type Result struct {
	// Document is the document to write. It differs from the input when a JSF
	// signature was embedded, which is why the caller must write this rather
	// than what it passed in.
	Document []byte
	// Identity is what the certificate says the signer is: the workflow
	// reference in CI, or the SPIFFE ID for a Vulnetix workload.
	Identity string
	// TlogEntryID is the transparency-log index and entry uuid.
	TlogEntryID string
	// Files are the sidecars written beside the document.
	Files []string
	// Skipped explains why nothing was signed. Empty when a signature was made.
	Skipped string
}

// Signed reports whether a signature was actually produced.
func (r Result) Signed() bool { return r.Skipped == "" }

// SignDocument signs data and writes the detached sidecars beside path.
//
// The sidecar names match what `cosign verify-blob` expects and what the
// Vulnetix release workflows already publish, so a consumer does not have to
// learn a second convention:
//
//	<path>.sig            base64 signature
//	<path>.pem            the short-lived certificate binding it to an identity
//	<path>.intoto.jsonl   the same claim as a DSSE envelope
//
// The returned document is what must be written to path: SignBytes embeds the
// JSF signature, and the detached signatures cover the result, so writing the
// input instead would publish bytes that none of the signatures match.
func SignDocument(ctx context.Context, path string, data []byte) (Result, error) {
	token, err := cyclonedx.AmbientIdentityToken(ctx, cyclonedx.SigstoreAudience)
	if err != nil {
		if errors.Is(err, cyclonedx.ErrNoAmbientIdentity) {
			return Result{
				Document: data,
				Skipped:  "no OIDC identity in this environment, so there is nothing to sign as",
			}, nil
		}
		return Result{Document: data}, err
	}

	signer := &cyclonedx.FulcioSigner{
		IdentityToken: func(context.Context, string) (string, error) { return token, nil },
		// Overridable so the same path can be pointed at a local instance,
		// which is how the identity is proven before anything depends on it.
		FulcioURL: os.Getenv("SIGSTORE_FULCIO_URL"),
		RekorURL:  os.Getenv("SIGSTORE_REKOR_URL"),
	}

	signed, err := cyclonedx.SignBytes(ctx, data, signer, cyclonedx.SignOptions{})
	if err != nil {
		return Result{Document: data}, err
	}

	result := Result{Document: signed.Document}

	for _, sig := range signed.Signatures {
		if result.Identity == "" {
			result.Identity = sig.KeyID
		}
		if result.TlogEntryID == "" {
			result.TlogEntryID = sig.TlogEntryID
		}

		switch sig.Format {
		case cyclonedx.SignatureFormatCosign:
			if err := writeSidecar(path+".sig", sig.Value, &result); err != nil {
				return result, err
			}
			if sig.CertificatePEM != "" {
				if err := writeSidecar(path+".pem", []byte(sig.CertificatePEM), &result); err != nil {
					return result, err
				}
			}
		case cyclonedx.SignatureFormatDSSE:
			if err := writeSidecar(path+".intoto.jsonl", sig.Value, &result); err != nil {
				return result, err
			}
		}
	}

	return result, nil
}

func writeSidecar(path string, data []byte, result *Result) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	result.Files = append(result.Files, path)
	return nil
}
