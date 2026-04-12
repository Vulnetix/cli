package license

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SPDXDocument represents an SPDX 2.3 JSON document.
type SPDXDocument struct {
	SPDXVersion           string                  `json:"spdxVersion"`
	DataLicense           string                  `json:"dataLicense"`
	SPDXID                string                  `json:"SPDXID"`
	Name                  string                  `json:"name"`
	DocumentNamespace     string                  `json:"documentNamespace"`
	CreationInfo          SPDXCreationInfo        `json:"creationInfo"`
	Packages              []SPDXPackage           `json:"packages"`
	Relationships         []SPDXRelationship      `json:"relationships,omitempty"`
	ExtractedLicensingInfos []SPDXExtractedLicense `json:"extractedLicensingInfos,omitempty"`
}

// SPDXCreationInfo describes when and by whom the SPDX document was created.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage is an SPDX package entry.
type SPDXPackage struct {
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	VersionInfo       string `json:"versionInfo,omitempty"`
	DownloadLocation  string `json:"downloadLocation"`
	LicenseConcluded  string `json:"licenseConcluded"`
	LicenseDeclared   string `json:"licenseDeclared"`
	CopyrightText     string `json:"copyrightText"`
	FilesAnalyzed     bool   `json:"filesAnalyzed"`
	ExternalRefs      []SPDXExternalRef `json:"externalRefs,omitempty"`
}

// SPDXExternalRef is a package external reference.
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXRelationship defines a relationship between SPDX elements.
type SPDXRelationship struct {
	Element     string `json:"spdxElementId"`
	RelType     string `json:"relationshipType"`
	RelatedElement string `json:"relatedSpdxElement"`
}

// SPDXExtractedLicense captures non-standard license text.
type SPDXExtractedLicense struct {
	LicenseID    string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
	Name         string `json:"name"`
}

// BuildSPDXDocument creates an SPDX 2.3 JSON document from license analysis results.
func BuildSPDXDocument(result *AnalysisResult, name string) *SPDXDocument {
	doc := &SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: fmt.Sprintf("https://vulnetix.com/spdx/%s", uuid.New().String()),
		CreationInfo: SPDXCreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: vulnetix-license-analyzer"},
		},
	}

	unknownLicenses := map[string]bool{}

	for i, pkg := range result.Packages {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)

		licenseConcluded := pkg.LicenseSpdxID
		if licenseConcluded == "UNKNOWN" {
			licenseConcluded = "NOASSERTION"
		}
		licenseDeclared := licenseConcluded
		if pkg.LicenseSource != "manifest" {
			licenseDeclared = "NOASSERTION"
		}

		sp := SPDXPackage{
			SPDXID:           spdxID,
			Name:             pkg.PackageName,
			VersionInfo:      pkg.PackageVersion,
			DownloadLocation: "NOASSERTION",
			LicenseConcluded: licenseConcluded,
			LicenseDeclared:  licenseDeclared,
			CopyrightText:    "NOASSERTION",
			FilesAnalyzed:    false,
		}

		// Add purl as external reference.
		if pkg.Ecosystem != "" {
			purl := fmt.Sprintf("pkg:%s/%s@%s", strings.ToLower(pkg.Ecosystem), pkg.PackageName, pkg.PackageVersion)
			sp.ExternalRefs = append(sp.ExternalRefs, SPDXExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}

		doc.Packages = append(doc.Packages, sp)

		// Track unknown licenses for extractedLicensingInfos.
		if pkg.LicenseSpdxID != "UNKNOWN" && LookupSPDX(pkg.LicenseSpdxID) == nil {
			unknownLicenses[pkg.LicenseSpdxID] = true
		}

		// Add DESCRIBES relationship from document.
		doc.Relationships = append(doc.Relationships, SPDXRelationship{
			Element:        "SPDXRef-DOCUMENT",
			RelType:        "DESCRIBES",
			RelatedElement: spdxID,
		})
	}

	// Add extracted licensing info for non-standard licenses.
	for lic := range unknownLicenses {
		doc.ExtractedLicensingInfos = append(doc.ExtractedLicensingInfos, SPDXExtractedLicense{
			LicenseID:     fmt.Sprintf("LicenseRef-%s", lic),
			ExtractedText: "License text not available",
			Name:          lic,
		})
	}

	return doc
}

// MarshalSPDXJSON serialises an SPDX document to indented JSON.
func MarshalSPDXJSON(doc *SPDXDocument) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}
