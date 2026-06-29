package cbom

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

var certExts = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".der": true,
	".key": true, ".pub": true, ".p7b": true, ".p7c": true,
}

// detectCerts parses certificate/key files on disk into certificate +
// related-crypto-material assets, and attributes their signature and public-key
// algorithms. Only type/size/validity metadata is read — never key material.
func (c *collector) detectCerts(input *sast.ScanInput) {
	if input == nil {
		return
	}
	for path := range input.FileSet {
		ext := strings.ToLower(filepath.Ext(path))
		if !certExts[ext] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.root, filepath.FromSlash(path)))
		if err != nil {
			continue
		}
		c.scanCertBytes(path, ext, data)
	}
}

func (c *collector) scanCertBytes(path, ext string, data []byte) {
	pemFound := false
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pemFound = true
		switch {
		case block.Type == "CERTIFICATE":
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				c.addCertificate(path, ext, cert)
			}
		case strings.Contains(block.Type, "PRIVATE KEY"), strings.Contains(block.Type, "PUBLIC KEY"):
			c.attributeKeyBlock(path, block.Type)
		}
		if len(rest) == 0 {
			break
		}
	}
	if !pemFound && (ext == ".der" || ext == ".cer" || ext == ".crt") {
		if cert, err := x509.ParseCertificate(data); err == nil {
			c.addCertificate(path, ext, cert)
		}
	}
}

func (c *collector) addCertificate(path, ext string, cert *x509.Certificate) {
	ev := cdx.CryptoEvidence{Method: "certificate", Category: "x509", Locator: path}
	pkName, size := pubKeyInfo(cert)
	pqc := cdx.PQCQuantumVulnerable

	if pkName != "" {
		if a, ok := c.cat.Lookup(pkName); ok {
			c.addAlgo(a, ev, "", "", "")
			if a.Def.PQCStatus != "" {
				pqc = a.Def.PQCStatus
			}
			pkName = a.Def.Name
		}
	}
	// Attribute the hash + scheme named by the signature algorithm string
	// (e.g. "SHA256-RSA" → SHA-256 + RSA).
	for _, tok := range splitNonAlnum(cert.SignatureAlgorithm.String()) {
		if a, ok := c.cat.Lookup(tok); ok {
			c.addAlgo(a, ev, "", "", "")
		}
	}

	c.certs = append(c.certs, cdx.CryptoCert{
		Name:               filepath.Base(path),
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		Format:             "X.509",
		FileExtension:      strings.TrimPrefix(ext, "."),
		SignatureAlgorithm: pkName,
		PublicKeyAlgorithm: pkName,
		PublicKeyType:      "public-key",
		KeySize:            size,
		PQCStatus:          pqc,
		Evidence:           []cdx.CryptoEvidence{ev},
	})
}

func (c *collector) attributeKeyBlock(path, blockType string) {
	ev := cdx.CryptoEvidence{Method: "certificate", Category: "key", Locator: path, Snippet: blockType}
	for _, tok := range splitNonAlnum(blockType) {
		if a, ok := c.cat.Lookup(tok); ok {
			c.addAlgo(a, ev, "", "", "")
		}
	}
}

// pubKeyInfo returns the canonical public-key algorithm name and key size in bits.
func pubKeyInfo(cert *x509.Certificate) (string, int) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return "RSA", k.N.BitLen()
		}
		return "RSA", 0
	case x509.ECDSA:
		if k, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return "ECDSA", k.Curve.Params().BitSize
		}
		return "ECDSA", 0
	case x509.Ed25519:
		return "Ed25519", 256
	case x509.DSA:
		return "DSA", 0
	}
	return "", 0
}

func splitNonAlnum(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
}
