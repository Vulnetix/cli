package tea

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Identifier is a TEA identifier: a type and its value.
type Identifier struct {
	IDType  string `json:"idType"`
	IDValue string `json:"idValue"`
}

// Product is a lineage of releases.
type Product struct {
	UUID        string       `json:"uuid"`
	Name        string       `json:"name"`
	Identifiers []Identifier `json:"identifiers,omitempty"`
}

// Release covers both flavours. The consumption API distinguishes a product
// release from a component release; the fields that differ are the parent and
// its name, so one struct carries both rather than duplicating the rest.
type Release struct {
	UUID          string       `json:"uuid"`
	Product       string       `json:"product,omitempty"`
	ProductName   string       `json:"productName,omitempty"`
	Component     string       `json:"component,omitempty"`
	ComponentName string       `json:"componentName,omitempty"`
	Version       string       `json:"version"`
	CreatedDate   string       `json:"createdDate,omitempty"`
	ReleaseDate   string       `json:"releaseDate,omitempty"`
	PreRelease    bool         `json:"preRelease,omitempty"`
	Identifiers   []Identifier `json:"identifiers,omitempty"`
}

// Checksum is one digest over an artifact format's bytes.
type Checksum struct {
	AlgType  string `json:"algType"`
	AlgValue string `json:"algValue"`
}

// Format is one representation of an artifact.
type Format struct {
	MediaType    string     `json:"mediaType"`
	Description  string     `json:"description,omitempty"`
	URL          string     `json:"url,omitempty"`
	SignatureURL string     `json:"signatureUrl,omitempty"`
	Checksums    []Checksum `json:"checksums,omitempty"`
}

// Artifact is one published document.
type Artifact struct {
	UUID        string   `json:"uuid"`
	Version     int      `json:"version,omitempty"`
	Name        string   `json:"name"`
	Type        string   `json:"type,omitempty"`
	CreatedDate string   `json:"createdDate,omitempty"`
	Formats     []Format `json:"formats,omitempty"`
}

// UpdateReason says why a collection changed. Required on publication: a
// collection whose contents change without saying why is indistinguishable, to
// a consumer, from one that was tampered with.
type UpdateReason struct {
	Type    string `json:"type"`
	Comment string `json:"comment,omitempty"`
}

// Collection is a versioned set of artifacts for one release.
type Collection struct {
	UUID         string        `json:"uuid"`
	Version      int           `json:"version"`
	Date         string        `json:"date,omitempty"`
	BelongsTo    string        `json:"belongsTo,omitempty"`
	UpdateReason *UpdateReason `json:"updateReason,omitempty"`
	Artifacts    []Artifact    `json:"artifacts,omitempty"`
}

// Page is the consumption API's pagination envelope.
type Page[T any] struct {
	Results       []T    `json:"results"`
	HasNext       bool   `json:"hasNext"`
	NextPageToken string `json:"nextPageToken"`
}

// ShareGrant entitles one organisation to read one object.
type ShareGrant struct {
	OrganizationUUID string `json:"organizationUuid"`
	OrganizationName string `json:"organizationName,omitempty"`
	ExpiresAt        int64  `json:"expiresAt,omitempty"`
}

// AccessPolicy is who may read an object.
type AccessPolicy struct {
	ObjectKind string       `json:"objectKind,omitempty"`
	ObjectUUID string       `json:"objectUuid,omitempty"`
	Visibility string       `json:"visibility"`
	SharedWith []ShareGrant `json:"sharedWith,omitempty"`
}

// AccessStatus reports what an object declares against what is enforced.
type AccessStatus struct {
	UUID          string        `json:"uuid"`
	Declared      *AccessPolicy `json:"declared,omitempty"`
	Effective     AccessPolicy  `json:"effective"`
	InheritedFrom string        `json:"inheritedFrom,omitempty"`
}

// ── Consumption ─────────────────────────────────────────────────────────────

// Products lists products.
func (c *Client) Products(ctx context.Context, pageSize int, pageToken string) (*Page[Product], error) {
	q := url.Values{}
	if pageSize > 0 {
		q.Set("pageSize", fmt.Sprint(pageSize))
	}
	if pageToken != "" {
		q.Set("pageToken", pageToken)
	}
	var out Page[Product]
	err := c.Do(ctx, "GET", "/products?"+q.Encode(), nil, &out, nil)
	return &out, err
}

// Product reads one product.
func (c *Client) Product(ctx context.Context, uuid string) (*Product, error) {
	var out Product
	err := c.Do(ctx, "GET", "/product/"+url.PathEscape(uuid), nil, &out, nil)
	return &out, err
}

// ProductReleases lists a product's releases.
func (c *Client) ProductReleases(ctx context.Context, uuid string) (*Page[Release], error) {
	var out Page[Release]
	err := c.Do(ctx, "GET", "/product/"+url.PathEscape(uuid)+"/releases?pageSize=100", nil, &out, nil)
	return &out, err
}

// LatestCollection reads the current collection for a product release.
func (c *Client) LatestCollection(ctx context.Context, releaseUUID string) (*Collection, error) {
	var out Collection
	err := c.Do(ctx, "GET", "/productRelease/"+url.PathEscape(releaseUUID)+"/collection/latest", nil, &out, nil)
	return &out, err
}

// ResolveTEI asks the server to resolve an identifier to the object it names.
func (c *Client) ResolveTEI(ctx context.Context, tei string) (map[string]any, error) {
	var out map[string]any
	err := c.Do(ctx, "GET", "/discovery?tei="+url.QueryEscape(tei), nil, &out, nil)
	return out, err
}

// ── Publication ─────────────────────────────────────────────────────────────

// CreateProduct registers a product. The server assigns the UUID and the TEI —
// a TEI names the server's authority over the object, which a publisher cannot
// assert on its behalf.
func (c *Client) CreateProduct(ctx context.Context, name string, identifiers []Identifier, idempotencyKey string) (*Product, error) {
	body := map[string]any{"name": name}
	if len(identifiers) > 0 {
		body["identifiers"] = identifiers
	}
	var out Product
	err := c.Do(ctx, "POST", "/product", body, &out, idempotencyHeader(idempotencyKey))
	return &out, err
}

// DeleteProduct removes a product and everything beneath it.
func (c *Client) DeleteProduct(ctx context.Context, uuid string) error {
	return c.Do(ctx, "DELETE", "/product/"+url.PathEscape(uuid), nil, nil, nil)
}

// CreateProductRelease publishes a release of a product.
func (c *Client) CreateProductRelease(ctx context.Context, productUUID, version, releaseDate string, preRelease bool, idempotencyKey string) (*Release, error) {
	body := map[string]any{
		"product":    productUUID,
		"version":    version,
		"preRelease": preRelease,
	}
	if releaseDate != "" {
		body["releaseDate"] = releaseDate
	}
	var out Release
	err := c.Do(ctx, "POST", "/productRelease", body, &out, idempotencyHeader(idempotencyKey))
	return &out, err
}

// PublishCollection publishes the next version of a release's collection.
func (c *Client) PublishCollection(ctx context.Context, releaseUUID string, reason UpdateReason) (*Collection, error) {
	var out Collection
	err := c.Do(ctx, "PUT", "/productRelease/"+url.PathEscape(releaseUUID)+"/collection",
		map[string]any{"updateReason": reason}, &out, nil)
	return &out, err
}

// CreateArtifact registers an artifact within a collection. It does not carry
// the bytes: those go up per format afterwards, so correcting a metadata field
// does not mean resending a multi-megabyte document.
func (c *Client) CreateArtifact(ctx context.Context, collectionUUID, name, artifactType string, formats []Format, idempotencyKey string) (*Artifact, error) {
	body := map[string]any{
		"collection": collectionUUID,
		"name":       name,
		"type":       artifactType,
		"formats":    formats,
	}
	var out Artifact
	err := c.Do(ctx, "POST", "/artifact", body, &out, idempotencyHeader(idempotencyKey))
	return &out, err
}

// UploadArtifactFile sends one format's bytes with the digest the server
// verifies against them.
func (c *Client) UploadArtifactFile(ctx context.Context, artifactUUID string, formatIndex int, path, mediaType string) (map[string]any, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if mediaType == "" {
		mediaType = MediaTypeForFile(path)
	}
	var out map[string]any
	err = c.Do(ctx, "PUT",
		fmt.Sprintf("/artifact/%s/format/%d/content", url.PathEscape(artifactUUID), formatIndex),
		body, &out, map[string]string{
			"Content-Type":   mediaType,
			"Content-Digest": ContentDigest(body),
		})
	return out, err
}

// AttachSignature records a detached signature and, crucially, the scheme it
// was produced with. The consumption API exposes only a URL, so a consumer
// without the scheme has to guess how to verify — which in practice means not
// verifying.
func (c *Client) AttachSignature(ctx context.Context, artifactUUID string, formatIndex int, sig map[string]any) error {
	return c.Do(ctx, "PUT",
		fmt.Sprintf("/artifact/%s/format/%d/signature", url.PathEscape(artifactUUID), formatIndex),
		sig, nil, nil)
}

// AccessPolicy reads the policy in force for an object.
func (c *Client) AccessPolicy(ctx context.Context, uuid string) (*AccessStatus, error) {
	var out AccessStatus
	err := c.Do(ctx, "GET", "/accessPolicy/"+url.PathEscape(uuid), nil, &out, nil)
	return &out, err
}

// SetAccessPolicy replaces an object's own policy.
//
// Going public requires the server's confirmation parameter. That is not
// ceremony: no later request undoes it, because whatever was fetched while an
// object was public stays fetched.
func (c *Client) SetAccessPolicy(ctx context.Context, uuid string, policy AccessPolicy) (*AccessStatus, error) {
	path := "/accessPolicy/" + url.PathEscape(uuid)
	if policy.Visibility == "public" {
		path += "?confirm=public"
	}
	var out AccessStatus
	err := c.Do(ctx, "PUT", path, policy, &out, nil)
	return &out, err
}

// Publications lists what this organisation has published, with the visibility
// of each — the half a publisher cannot see through the consumption API,
// because that API will not show anyone anything private.
func (c *Client) Publications(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Products []map[string]any `json:"products"`
	}
	err := c.Do(ctx, "GET", "/publications", nil, &out, nil)
	return out.Products, err
}

func idempotencyHeader(key string) map[string]string {
	if strings.TrimSpace(key) == "" {
		return nil
	}
	return map[string]string{"Idempotency-Key": key}
}

// MediaTypeForFile guesses the media type of a transparency document from its
// name.
//
// Only the formats TEA actually carries are recognised. Anything else becomes
// application/octet-stream rather than a guess: an artifact served under the
// wrong media type is one a consumer's parser will reject, and being wrong is
// worse than being unspecific.
func MediaTypeForFile(path string) string {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(name, ".cdx.json"), strings.Contains(name, "cyclonedx"), strings.Contains(name, ".cdx."):
		return "application/vnd.cyclonedx+json"
	case strings.HasSuffix(name, ".spdx.json"), strings.Contains(name, "spdx"):
		return "application/spdx+json"
	case strings.HasSuffix(name, ".sarif"), strings.HasSuffix(name, ".sarif.json"):
		return "application/sarif+json"
	case strings.Contains(name, "vex"):
		return "application/vnd.openvex+json"
	case strings.HasSuffix(name, ".json"):
		return "application/json"
	case strings.HasSuffix(name, ".md"), strings.HasSuffix(name, ".txt"):
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

// ArtifactTypeForFile maps a document to the TEA artifact type enum.
//
// Defaults to OTHER rather than BOM: claiming a file is a bill of materials
// when it might not be tells a consumer to parse it as one.
func ArtifactTypeForFile(path string) string {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(name, "vex"):
		return "VULNERABILITIES"
	case strings.Contains(name, "cyclonedx"), strings.Contains(name, ".cdx."),
		strings.Contains(name, "spdx"), strings.Contains(name, "sbom"),
		strings.Contains(name, "cbom"), strings.Contains(name, "aibom"):
		return "BOM"
	case strings.HasSuffix(name, ".sarif"), strings.HasSuffix(name, ".sarif.json"):
		return "VULNERABILITIES"
	case strings.Contains(name, "attestation"), strings.Contains(name, "provenance"),
		strings.Contains(name, "slsa"):
		return "ATTESTATION"
	case strings.Contains(name, "release-note"), strings.Contains(name, "changelog"):
		return "RELEASE_NOTES"
	case strings.Contains(name, "license"), strings.Contains(name, "licence"):
		return "LICENSE"
	default:
		return "OTHER"
	}
}
