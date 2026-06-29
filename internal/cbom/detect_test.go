package cbom

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func compiledCatalog(t *testing.T) *CompiledCatalog {
	t.Helper()
	cat, err := LoadCatalog("", false)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	cc, err := cat.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return cc
}

func detect(t *testing.T, dir string, opts Options) map[string]*assetView {
	t.Helper()
	opts.Root = dir
	opts.Catalog = compiledCatalog(t)
	det, err := Detect(opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	out := map[string]*assetView{}
	for _, a := range det.Assets {
		out[a.SPDXID] = &assetView{name: a.Name, pqc: a.PQCStatus, occur: a.Occurrences}
	}
	return out
}

type assetView struct {
	name  string
	pqc   string
	occur int
}

func TestNormalizeFolding(t *testing.T) {
	cases := map[string]string{
		"SHA256": "sha256", "Sha256": "sha256", "sha256": "sha256", "SHA_256": "sha256",
		"SHA-256": "sha256", "ML-KEM-768": "mlkem768", "NTRU+": "ntru+",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSHA256VariantEquivalence is the explicit requirement: SHA256 / Sha256 /
// sha256 / SHA_256 must all resolve to the one canonical SPDX algorithm.
func TestSHA256VariantEquivalence(t *testing.T) {
	cc := compiledCatalog(t)
	for _, v := range []string{"SHA256", "Sha256", "sha256", "SHA_256", "SHA-256"} {
		a, ok := cc.Lookup(v)
		if !ok {
			t.Fatalf("Lookup(%q) failed", v)
		}
		if a.Def.ID != "sha-256" || a.Def.Name != "SHA-256" {
			t.Errorf("Lookup(%q) = %s/%s, want sha-256/SHA-256", v, a.Def.ID, a.Def.Name)
		}
	}
}

func TestCatalogCompiles(t *testing.T) {
	cc := compiledCatalog(t)
	if len(cc.Algorithms) < 20 {
		t.Errorf("expected a substantial algorithm catalog, got %d", len(cc.Algorithms))
	}
	if _, ok := cc.Lookup("ml-kem-768"); !ok {
		t.Error("ML-KEM-768 not in catalog")
	}
}

func TestDetectSourceGo(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "crypto.go", `package main
import (
	_ "crypto/aes"
	_ "crypto/md5"
	_ "crypto/sha256"
)
`)
	assets := detect(t, dir, Options{ScanSource: true})
	for id, wantPQC := range map[string]string{"aes": "quantum-safe", "md5": "deprecated", "sha-256": "quantum-safe"} {
		a, ok := assets[id]
		if !ok {
			t.Fatalf("expected %s detected; got %v", id, keys(assets))
		}
		if a.pqc != wantPQC {
			t.Errorf("%s pqc = %q, want %q", id, a.pqc, wantPQC)
		}
	}
}

// TestDetectSourceCaseInsensitive proves variant spellings merge into one asset.
func TestDetectSourceCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.js", `const crypto = require('crypto');
crypto.createHash('SHA256');
crypto.createHash('sha-256');
crypto.createHash('Sha256');
`)
	assets := detect(t, dir, Options{ScanSource: true})
	a, ok := assets["sha-256"]
	if !ok {
		t.Fatalf("sha-256 not detected; got %v", keys(assets))
	}
	if a.occur != 3 {
		t.Errorf("occurrences = %d, want 3 (all variants merged into one asset)", a.occur)
	}
	if len(assets) != 1 {
		t.Errorf("expected exactly one merged asset, got %v", keys(assets))
	}
}

func TestDetectConfigCipherSuites(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "nginx.conf", `
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
`)
	assets := detect(t, dir, Options{ScanConfig: true})
	for _, id := range []string{"aes", "ecdh", "rsa", "ecdsa", "sha-256", "sha-384"} {
		if _, ok := assets[id]; !ok {
			t.Errorf("expected %s from cipher suites; got %v", id, keys(assets))
		}
	}
}

func TestDetectConfigHybridPQC(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "tls.conf", "ssl_ecdh_curve X25519MLKEM768;\n")
	assets := detect(t, dir, Options{ScanConfig: true})
	a, ok := assets["x25519-mlkem768"]
	if !ok {
		t.Fatalf("hybrid X25519MLKEM768 not detected; got %v", keys(assets))
	}
	if a.pqc != "hybrid" {
		t.Errorf("pqc = %q, want hybrid", a.pqc)
	}
}

func TestDetectCertificate(t *testing.T) {
	dir := t.TempDir()
	writeSelfSignedRSACert(t, dir, "server.pem")
	opts := Options{ScanCerts: true, Root: dir, Catalog: compiledCatalog(t)}
	det, err := Detect(opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(det.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(det.Certificates))
	}
	cert := det.Certificates[0]
	if cert.PublicKeyAlgorithm != "RSA" || cert.KeySize != 2048 {
		t.Errorf("cert pubkey = %s/%d, want RSA/2048", cert.PublicKeyAlgorithm, cert.KeySize)
	}
	if cert.PQCStatus != "quantum-vulnerable" {
		t.Errorf("cert pqc = %q, want quantum-vulnerable", cert.PQCStatus)
	}
	var hasRSA bool
	for _, a := range det.Assets {
		if a.SPDXID == "rsa" {
			hasRSA = true
		}
	}
	if !hasRSA {
		t.Error("RSA algorithm asset not attributed from certificate")
	}
}

func TestDetectDepsCargo(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Cargo.toml", "[dependencies]\nring = \"0.17\"\n")
	opts := Options{ScanDeps: true, Root: dir, Catalog: compiledCatalog(t)}
	det, err := Detect(opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	var found bool
	for _, l := range det.Libraries {
		if l.ID == "ring" {
			found = true
		}
	}
	if !found {
		t.Errorf("ring crypto library not detected; got %d libs", len(det.Libraries))
	}
}

// ---- helpers ----

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func keys(m map[string]*assetView) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func writeSelfSignedRSACert(t *testing.T, dir, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	write(t, dir, name, string(pemBytes))
}
