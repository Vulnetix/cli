package vdb

// ─── /v2/cli.image and /v2/cli.container-sources ────────────────────────────
// What container curation needs from the CLI: a container image's identity,
// layer chain, traits and packages per layer (`vulnetix image`), and each
// Dockerfile FROM and install line (`vulnetix containers`). The server owns
// the contract; these mirror vdb-api's handler types.

// CliImageRequest is the payload for POST /v2/cli.image.
type CliImageRequest struct {
	Ref                string             `json:"ref"`
	Registry           string             `json:"registry,omitempty"`
	Repository         string             `json:"repository,omitempty"`
	Tag                string             `json:"tag,omitempty"`
	Digest             string             `json:"digest"`
	ManifestListDigest string             `json:"manifestListDigest,omitempty"`
	Platform           string             `json:"platform,omitempty"`
	DiffIDs            []string           `json:"diffIds"`
	Labels             map[string]string  `json:"labels,omitempty"`
	OS                 string             `json:"os,omitempty"`
	OSRelease          string             `json:"osRelease,omitempty"`
	PurlDistro         string             `json:"purlDistro,omitempty"`
	Libc               string             `json:"libc,omitempty"`
	HasShell           *bool              `json:"hasShell,omitempty"`
	NonRoot            *bool              `json:"nonRoot,omitempty"`
	DefaultUser        string             `json:"defaultUser,omitempty"`
	PkgManager         string             `json:"pkgManager,omitempty"`
	RuntimeName        string             `json:"runtimeName,omitempty"`
	RuntimeVersion     string             `json:"runtimeVersion,omitempty"`
	Packages           []CliImagePackage  `json:"packages"`
	Source             *CliImageSourceRef `json:"source,omitempty"`
}

// CliImagePackage is one package with the layer that installed it.
type CliImagePackage struct {
	Purl        string `json:"purl"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	LayerIndex  *int   `json:"layerIndex,omitempty"`
	LayerDigest string `json:"layerDigest,omitempty"`
}

// CliImageSourceRef names the repository that built the image.
type CliImageSourceRef struct {
	RepoFullName string `json:"repoFullName"`
	FilePath     string `json:"filePath,omitempty"`
}

// CliImageResponse is what /v2/cli.image recorded.
type CliImageResponse struct {
	ContainerUuid     string `json:"containerUuid"`
	PackagesStored    int    `json:"packagesStored"`
	BaseResolution    string `json:"baseResolution"`
	BaseRef           string `json:"baseRef"`
	BaseMatchedLayers int    `json:"baseMatchedLayers"`
	WorkloadsLinked   int    `json:"workloadsLinked"`
	Persisted         bool   `json:"persisted"`
}

// CliImage — POST /v2/cli.image. Gzipped: an image's package list is large.
func (c *Client) CliImage(env CliEnv, req CliImageRequest) (*CliResponse[CliImageResponse], error) {
	return cliPostWithEnvGzip[CliImageResponse](c, "cli.image", env, req)
}

// CliContainerSourcesRequest is the payload for POST /v2/cli.container-sources.
type CliContainerSourcesRequest struct {
	RepoFullName string                   `json:"repoFullName,omitempty"`
	CommitSha    string                   `json:"commitSha,omitempty"`
	Files        []CliContainerSourceFile `json:"files"`
}

// CliContainerSourceFile is one Dockerfile.
type CliContainerSourceFile struct {
	Path   string                    `json:"path"`
	Stages []CliContainerSourceStage `json:"stages"`
}

// CliContainerSourceStage is one FROM and the install lines after it.
type CliContainerSourceStage struct {
	Index          int                         `json:"index"`
	Name           string                      `json:"name,omitempty"`
	Line           int                         `json:"line"`
	RawRef         string                      `json:"rawRef"`
	ResolvedRef    string                      `json:"resolvedRef,omitempty"`
	FromStage      string                      `json:"fromStage,omitempty"`
	Platform       string                      `json:"platform,omitempty"`
	IsFinal        bool                        `json:"isFinal"`
	UnresolvedArgs bool                        `json:"unresolvedArgs,omitempty"`
	Installs       []CliContainerSourceInstall `json:"installs,omitempty"`
}

// CliContainerSourceInstall is one package-manager install line.
type CliContainerSourceInstall struct {
	Line     int                         `json:"line"`
	Manager  string                      `json:"manager"`
	Packages []CliContainerSourcePackage `json:"packages"`
}

// CliContainerSourcePackage is a package as the install line wrote it.
type CliContainerSourcePackage struct {
	Name string `json:"name"`
	Spec string `json:"spec,omitempty"`
}

// CliContainerSourcesResponse is what /v2/cli.container-sources recorded.
type CliContainerSourcesResponse struct {
	RepoFullName string `json:"repoFullName"`
	Stages       int    `json:"stages"`
	Installs     int    `json:"installs"`
	LinkedImages int    `json:"linkedImages"`
	Persisted    bool   `json:"persisted"`
}

// CliContainerSources — POST /v2/cli.container-sources.
func (c *Client) CliContainerSources(env CliEnv, req CliContainerSourcesRequest) (*CliResponse[CliContainerSourcesResponse], error) {
	return cliPostWithEnv[CliContainerSourcesResponse](c, "cli.container-sources", env, req)
}
