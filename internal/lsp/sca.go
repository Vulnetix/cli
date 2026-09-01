package lsp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Vulnetix/vdb-sca-match/parse"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/lsp/anchor"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/cache"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// scaChunkSize is how many purls go in one cli.sca request.
//
// Smaller than the scan command's 25, deliberately. That batch size is tuned
// for a one-shot command where the only thing that matters is total wall time.
// The editor wants two different things: partial results that can be published
// as they arrive, and batches small enough that a slow upstream answers rather
// than hitting a gateway timeout — a 504 costs the whole batch and the full
// deadline before anything can be retried. Halving on transient failure covers
// the rest.
const scaChunkSize = 10

// scaRequestTimeoutDefault bounds a single batch.
//
// Matches the scan command's default rather than picking an editor-specific
// one. A cold bulk query for a whole workspace is the same work whoever asked
// for it, and a shorter deadline here would make the editor report "no
// dependency data" for a query the terminal completes.
//
// Bounded rather than unbounded because a language server that hangs on a slow
// network is worse than one that reports nothing: the user keeps typing either
// way, and a stalled request holds a worker.
const scaRequestTimeoutDefault = 75 * time.Second

// scaRequestTimeout is the per-batch deadline, honouring the same environment
// override the scan command accepts so a slow or self-hosted deployment is
// configured in one place.
func scaRequestTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("VULNETIX_SCA_TIMEOUT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return min(max(time.Duration(n)*time.Second, 10*time.Second), 300*time.Second)
		}
	}
	return scaRequestTimeoutDefault
}

// scaVerdict is everything known about one package, accumulated across both
// lookup phases.
type scaVerdict struct {
	Purl      string
	Name      string
	Version   string
	Ecosystem string

	// SourceFile is the repository-relative manifest that declared the package.
	SourceFile string
	IsDirect   bool

	// Vulns is the phase-one result: empty means the bulk check cleared this
	// package, which is what earns it the quiet "checked" marker.
	Vulns []scan.EnrichedVuln

	// Insight is the phase-two result, nil until Safe-Harbour has been resolved
	// for this package. SafeState distinguishes "not asked yet" from "asked and
	// the server had nothing", which render differently.
	Insight   *vdb.CliPackageInsight
	SafeState safeState
}

// safeState tracks the deferred Safe-Harbour lookup for one package.
type safeState int

const (
	// safeUnrequested means phase two has not run for this package. A clean
	// package stays here forever: there is nothing to recommend.
	safeUnrequested safeState = iota
	// safePending means a request is in flight, which is what the editor renders
	// as a loading marker.
	safePending
	// safeResolved means the answer arrived, whether or not it contained a
	// usable version.
	safeResolved
)

// Vulnerable reports whether the bulk check found anything.
func (v *scaVerdict) Vulnerable() bool { return len(v.Vulns) > 0 }

// scaEngine owns the workspace dependency picture and the VDB client.
//
// It is deliberately separate from the rule session: SAST analysis is a pure
// local evaluation and must stay that way, while this is the one part of the
// server that talks to the network.
type scaEngine struct {
	logf func(string, ...any)
	// version namespaces the on-disk response cache.
	version string

	mu sync.Mutex
	// client is built lazily so a workspace with no manifests never constructs
	// one, and so a credential change is picked up on the next scan.
	client *vdb.Client
	// plan is the tier reported in the rate-limit headers.
	plan string
	// tier is the tier named in the response body, which is authoritative where
	// the two disagree, and gated names the features the server withheld.
	tier  string
	gated map[string]bool

	root string
	cfg  scaSettings

	// packagesByFile maps a repository-relative manifest path to the packages it
	// declared, and typeByFile to the manifest type that parsed it.
	packagesByFile map[string][]scan.ScopedPackage
	typeByFile     map[string]string
	// groups carries the direct/transitive graphs, when a lockfile supplied one.
	groups []scan.ManifestGroup

	// verdicts is keyed by purl. Packages appearing in several manifests share
	// one verdict; SourceFile records where it was first declared.
	verdicts map[string]*scaVerdict

	// scanned marks that a bulk pass has completed at least once, so the
	// document path can tell "clean" from "not looked at yet". Publishing an
	// empty list before the first pass would read as a clean bill of health.
	scanned bool
}

func newSCAEngine(version string, logf func(string, ...any)) *scaEngine {
	return &scaEngine{
		logf:           logf,
		version:        version,
		packagesByFile: map[string][]scan.ScopedPackage{},
		typeByFile:     map[string]string{},
		verdicts:       map[string]*scaVerdict{},
		cfg:            defaultSCASettings(),
	}
}

func (e *scaEngine) log(format string, args ...any) {
	if e.logf != nil {
		e.logf(format, args...)
	}
}

// SetSettings replaces the engine's configuration. Values are already clamped by
// the settings layer; this never sees a raw user value.
func (e *scaEngine) SetSettings(cfg scaSettings) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
}

func (e *scaEngine) settings() scaSettings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// Ready reports whether a bulk pass has completed.
func (e *scaEngine) Ready() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scanned
}

// ── Phase one: bulk declared-dependency check ────────────────────────────────

// Discover walks the workspace for manifests and parses each one, preferring the
// editor's buffer over the file on disk so an unsaved edit is what gets checked.
//
// overlay maps repository-relative paths to open buffer text.
func (e *scaEngine) Discover(root string, overlay map[string]string) error {
	files, err := scan.WalkForScanFiles(scan.WalkOptions{
		RootPath: root,
		MaxDepth: 4,
		// Deliberately false: dependency manifests routinely live in gitignored
		// install directories, and the walker already prunes ecosystem install
		// dirs by name.
		RespectGitignore: false,
	})
	if err != nil {
		return fmt.Errorf("walking for manifests: %w", err)
	}

	packagesByFile := map[string][]scan.ScopedPackage{}
	typeByFile := map[string]string{}
	ecosystemByFile := map[string]string{}

	for _, f := range files {
		if f.ManifestInfo == nil {
			continue
		}
		rel := normaliseRelPath(f.RelPath)

		data, ok := overlay[rel]
		var content []byte
		if ok {
			content = []byte(data)
		} else {
			b, readErr := os.ReadFile(f.Path)
			if readErr != nil {
				continue
			}
			content = b
		}

		pkgs, parseErr := parse.ParseManifest(content, f.ManifestInfo.Type, rel)
		if parseErr != nil || len(pkgs) == 0 {
			continue
		}
		packagesByFile[rel] = pkgs
		typeByFile[rel] = f.ManifestInfo.Type
		ecosystemByFile[rel] = f.ManifestInfo.Ecosystem
	}

	groups := scan.BuildManifestGroups(packagesByFile, ecosystemByFile)

	e.mu.Lock()
	e.root = root
	e.packagesByFile = packagesByFile
	e.typeByFile = typeByFile
	e.groups = groups
	e.mu.Unlock()

	return nil
}

// RunBulk performs the phase-one lookup for every declared package.
//
// Only the cheap verdict is requested: CliSCAOptions gates Safe-Harbour, EOL and
// malware behind explicit flags precisely so a plain check pays nothing for
// them. Those arrive in phase two, for the manifest the user actually opened.
func (e *scaEngine) RunBulk(ctx context.Context) error {
	e.mu.Lock()
	packages := flattenPackages(e.packagesByFile)
	e.mu.Unlock()

	if len(packages) == 0 {
		e.mu.Lock()
		e.scanned = true
		e.mu.Unlock()
		return nil
	}

	purlByIndex, unique := buildPurls(packages)
	if len(unique) == 0 {
		e.mu.Lock()
		e.scanned = true
		e.mu.Unlock()
		return nil
	}

	client, err := e.ensureClient()
	if err != nil {
		return err
	}

	merged, err := e.runChunks(ctx, client, unique, vdb.CliSCAOptions{
		IncludeReachability: boolPtr(false),
	})
	if err != nil {
		return err
	}

	_, enriched, _ := scan.SynthesiseFromCDX(merged, packages, purlByIndex)

	// Group by purl, keeping each advisory once per package.
	//
	// The deduplication is required, not tidiness. A package declared in both a
	// manifest and its lockfile appears twice in the package list, and
	// SynthesiseFromCDX emits one finding per declaration, so a straight append
	// reports "24 vulnerabilities" for a package with twelve and doubles every
	// exploit count on the hover card.
	vulnsByPurl := map[string][]scan.EnrichedVuln{}
	seenVuln := map[string]bool{}
	for _, v := range enriched {
		purl := cdx.BuildLocalPurl(v.PackageName, v.PackageVer, v.Ecosystem)
		if purl == "" {
			continue
		}
		key := purl + "\x00" + v.CveID
		if seenVuln[key] {
			continue
		}
		seenVuln[key] = true
		vulnsByPurl[purl] = append(vulnsByPurl[purl], v)
	}

	verdicts := make(map[string]*scaVerdict, len(unique))
	for i, p := range packages {
		purl := purlByIndex[i]
		if purl == "" {
			continue
		}
		if existing, ok := verdicts[purl]; ok {
			// The same package declared in two manifests: keep the first
			// declaration site, but let a direct declaration win over a
			// transitive one so the fix is offered where it can be applied.
			if !existing.IsDirect && p.IsDirect {
				existing.IsDirect = true
				existing.SourceFile = normaliseRelPath(p.SourceFile)
			}
			continue
		}
		verdicts[purl] = &scaVerdict{
			Purl:       purl,
			Name:       p.Name,
			Version:    p.Version,
			Ecosystem:  p.Ecosystem,
			SourceFile: normaliseRelPath(p.SourceFile),
			IsDirect:   p.IsDirect,
			Vulns:      vulnsByPurl[purl],
		}
	}

	e.mu.Lock()
	// Carry forward any Safe-Harbour already resolved for a package whose
	// verdict is unchanged, so a save does not throw away phase-two work.
	for purl, next := range verdicts {
		if prev, ok := e.verdicts[purl]; ok && prev.Version == next.Version {
			next.Insight = prev.Insight
			next.SafeState = prev.SafeState
		}
	}
	e.verdicts = verdicts
	e.scanned = true
	e.mu.Unlock()

	e.log("sca: checked %d package(s), %d with findings", len(verdicts), countVulnerable(verdicts))
	return nil
}

// ── Phase two: deferred Safe-Harbour ─────────────────────────────────────────

// EnsureSafeVersions resolves Safe-Harbour data for the vulnerable packages of
// one manifest.
//
// Deferred to the open document on purpose. The bulk pass answers "is anything
// wrong here", which is what the workspace needs; ranked replacement versions
// are only useful for a file someone is looking at, and asking for them costs
// per-package work on the server.
//
// Returns the purls whose state changed, so the caller knows whether to
// republish. Packages already pending or resolved are not re-requested.
func (e *scaEngine) EnsureSafeVersions(ctx context.Context, relPath string) ([]string, error) {
	e.mu.Lock()
	pending := make([]string, 0, 8)
	for _, v := range e.verdicts {
		if !v.Vulnerable() || v.SourceFile != relPath || v.SafeState != safeUnrequested {
			continue
		}
		v.SafeState = safePending
		pending = append(pending, v.Purl)
	}
	e.mu.Unlock()

	if len(pending) == 0 {
		return nil, nil
	}

	client, err := e.ensureClient()
	if err != nil {
		e.resetPending(pending)
		return pending, err
	}

	insights, err := e.runInsightChunks(ctx, client, pending)
	if err != nil {
		e.resetPending(pending)
		return pending, err
	}

	byPurl := make(map[string]vdb.CliPackageInsight, len(insights))
	for _, ins := range insights {
		byPurl[ins.Purl] = ins
	}

	e.log("sca: resolved safe versions for %d of %d package(s); tier=%q gated=%v",
		len(byPurl), len(pending), e.Tier(), e.gatedFeatures())

	e.mu.Lock()
	for _, purl := range pending {
		v, ok := e.verdicts[purl]
		if !ok {
			continue
		}
		v.SafeState = safeResolved
		if ins, found := byPurl[purl]; found {
			copied := ins
			v.Insight = &copied
		}
	}
	e.mu.Unlock()

	return pending, nil
}

// resetPending returns packages to the unrequested state after a failed lookup,
// so opening the file again retries rather than showing a spinner forever.
func (e *scaEngine) resetPending(purls []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, purl := range purls {
		if v, ok := e.verdicts[purl]; ok && v.SafeState == safePending {
			v.SafeState = safeUnrequested
		}
	}
}

// ── Requests ─────────────────────────────────────────────────────────────────

// runChunks issues the batched cli.sca requests and merges their CycloneDX
// payloads into one document.
//
// A partial result is still a result: if one batch fails after splitting, the
// rest are reported, because showing the vulnerabilities that were confirmed
// beats showing none. Only a total failure is an error, so the caller can leave
// the previous state alone rather than publishing an empty list — which would
// read as "clean".
func (e *scaEngine) runChunks(ctx context.Context, client *vdb.Client, purls []string, opts vdb.CliSCAOptions) (map[string]any, error) {
	results, err := e.sendBatches(ctx, client, purls, opts)
	if len(results) == 0 {
		return nil, fmt.Errorf("dependency lookup failed: %w", err)
	}
	if err != nil {
		e.log("sca: dependency lookup was partial: %v", err)
	}

	components := make([]any, 0, len(purls))
	vulns := make([]any, 0)
	for _, r := range results {
		components = append(components, r.Components...)
		vulns = append(vulns, r.Vulns...)
	}

	return map[string]any{
		"bomFormat":       "CycloneDX",
		"specVersion":     "1.6",
		"components":      components,
		"vulnerabilities": vulns,
	}, nil
}

// runInsightChunks issues the phase-two requests, which ask for the per-package
// policy signals the diagnostic and the quick fix render.
func (e *scaEngine) runInsightChunks(ctx context.Context, client *vdb.Client, purls []string) ([]vdb.CliPackageInsight, error) {
	results, err := e.sendBatches(ctx, client, purls, vdb.CliSCAOptions{
		IncludeReachability: boolPtr(false),
		IncludeSafeVersions: true,
		IncludeEOL:          true,
		IncludeMalware:      true,
	})
	if len(results) == 0 {
		return nil, fmt.Errorf("safe-version lookup failed: %w", err)
	}
	if err != nil {
		e.log("sca: safe-version lookup was partial: %v", err)
	}

	out := make([]vdb.CliPackageInsight, 0, len(purls))
	for _, r := range results {
		out = append(out, r.Insights...)
	}
	return out, nil
}

// ensureClient builds the VDB client on first use.
//
// Mirrors the scan command's construction so the editor and the terminal
// resolve the same credentials, honour the same API override and share the same
// on-disk cache. Signing in is not required: the CLI ships community
// credentials, and the extension advertises that scanning works signed out.
func (e *scaEngine) ensureClient() (*vdb.Client, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.client != nil {
		return e.client, nil
	}

	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil {
		creds = auth.CommunityCredentials()
	}
	if creds == nil {
		return nil, fmt.Errorf("no credentials available for dependency lookup")
	}

	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	if u := strings.TrimSpace(os.Getenv("VULNETIX_API_URL")); u != "" {
		client.BaseURL = strings.TrimRight(u, "/")
	}
	if client.HTTPClient != nil {
		// Generous relative to the per-batch deadline: this client also fetches
		// the auth token, and starving that would fail the batch for a reason
		// that has nothing to do with how long the query takes.
		client.HTTPClient.Timeout = scaRequestTimeout() + 30*time.Second
	}
	if dc, cacheErr := cache.NewDiskCache(e.cliVersion()); cacheErr == nil {
		client.Cache = dc
	}

	e.client = client
	return client, nil
}

// cliVersion is the version string the disk cache namespaces entries by. Held
// separately so the engine does not depend on the cmd package's build vars.
func (e *scaEngine) cliVersion() string {
	if e.version == "" {
		return "dev"
	}
	return e.version
}

// recordPlan captures the tier the API reported, which decides whether exploit
// intelligence is rendered or advertised.
func (e *scaEngine) recordPlan(client *vdb.Client) {
	if rl := client.LastRateLimit; rl != nil && rl.Plan != "" {
		e.mu.Lock()
		e.plan = rl.Plan
		e.mu.Unlock()
	}
}

// Plan returns the last reported subscription tier, empty when unknown.
func (e *scaEngine) Plan() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.plan
}

// env describes the caller to the API. The editor identifies itself as the
// language server so server-side analytics can tell editor traffic from CI.
func (e *scaEngine) env() vdb.CliEnv {
	e.mu.Lock()
	root := e.root
	version := e.version
	e.mu.Unlock()
	return vdb.SnapshotEnv(root, version, "", "")
}

// ── Lookups used by the document features ────────────────────────────────────

// PackagesFor returns the packages declared by one manifest, and its type.
func (e *scaEngine) PackagesFor(relPath string) ([]scan.ScopedPackage, string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	pkgs, ok := e.packagesByFile[relPath]
	if !ok {
		return nil, "", false
	}
	return pkgs, e.typeByFile[relPath], true
}

// VerdictFor returns the verdict for a package coordinate.
func (e *scaEngine) VerdictFor(name, version, ecosystem string) (*scaVerdict, bool) {
	purl := cdx.BuildLocalPurl(name, version, ecosystem)
	if purl == "" {
		return nil, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.verdicts[purl]
	return v, ok
}

// IsManifest reports whether the engine parsed this path as a manifest.
func (e *scaEngine) IsManifest(relPath string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.typeByFile[relPath]
	return ok
}

// ManifestPaths returns every parsed manifest path.
func (e *scaEngine) ManifestPaths() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.typeByFile))
	for p := range e.typeByFile {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// IntroducedBy returns the direct dependencies in relPath that pull in a
// transitive package, so a lockfile-only vulnerability can also be surfaced on
// the manifest line the user can actually act on.
//
// Empty when no dependency graph was available: without a lockfile there is no
// evidence for the claim, and inventing a parent would point the fix at the
// wrong package.
func (e *scaEngine) IntroducedBy(relPath, pkgName string) []string {
	e.mu.Lock()
	groups := e.groups
	e.mu.Unlock()

	dir := filepath.ToSlash(filepath.Dir(relPath))
	seen := map[string]bool{}
	var out []string

	for _, g := range groups {
		if filepath.ToSlash(g.Dir) != dir || g.Graph == nil {
			continue
		}
		if g.Graph.IsDirect(pkgName) {
			continue
		}
		for parent, children := range g.Graph.Edges {
			for _, child := range children {
				if child != pkgName || !g.Graph.IsDirect(parent) || seen[parent] {
					continue
				}
				seen[parent] = true
				out = append(out, parent)
			}
		}
	}
	sort.Strings(out)
	return out
}

// AnchorFor resolves the line in a manifest that declares a package.
func (e *scaEngine) AnchorFor(relPath, text, pkgName string) (anchor.Result, bool) {
	e.mu.Lock()
	manifestType := e.typeByFile[relPath]
	e.mu.Unlock()
	if manifestType == "" {
		return anchor.Result{}, false
	}
	return anchor.Find(text, manifestType, pkgName)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func flattenPackages(byFile map[string][]scan.ScopedPackage) []scan.ScopedPackage {
	paths := make([]string, 0, len(byFile))
	for p := range byFile {
		paths = append(paths, p)
	}
	// Sorted so the same workspace produces the same request order, which makes
	// the disk cache useful across restarts.
	sort.Strings(paths)

	out := make([]scan.ScopedPackage, 0, 64)
	for _, p := range paths {
		out = append(out, byFile[p]...)
	}
	return out
}

// buildPurls returns the per-package purl (index-aligned with packages, as
// SynthesiseFromCDX expects) and the deduplicated set to request.
func buildPurls(packages []scan.ScopedPackage) ([]string, []string) {
	byIndex := make([]string, len(packages))
	seen := map[string]bool{}
	unique := make([]string, 0, len(packages))

	for i, p := range packages {
		purl := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		byIndex[i] = purl
		if purl == "" || seen[purl] {
			continue
		}
		seen[purl] = true
		unique = append(unique, purl)
	}
	return byIndex, unique
}

func chunkStrings(in []string, size int) [][]string {
	if size <= 0 {
		return [][]string{in}
	}
	out := make([][]string, 0, (len(in)+size-1)/size)
	for i := 0; i < len(in); i += size {
		end := i + size
		if end > len(in) {
			end = len(in)
		}
		out = append(out, in[i:end])
	}
	return out
}

func countVulnerable(verdicts map[string]*scaVerdict) int {
	n := 0
	for _, v := range verdicts {
		if v.Vulnerable() {
			n++
		}
	}
	return n
}

func boolPtr(b bool) *bool { return &b }

// normaliseRelPath puts a repository-relative path into the one form the rest
// of the server uses.
//
// The manifest walker reports paths as "./package.json" because that is what
// reads well in terminal output, while RelPathFor produces "package.json" from
// a document URI. Both are the same file, and keying maps by the raw strings
// silently matches nothing: the dependency picture is built, and then every
// lookup from an open document misses it.
func normaliseRelPath(p string) string {
	p = filepath.ToSlash(p)
	p = strings.TrimPrefix(p, "./")
	return strings.TrimPrefix(p, "/")
}

// recordTier captures the subscription tier and the features the server said it
// withheld.
//
// The response is the authority on this, not the credentials: an account can be
// on a plan the client has no way to infer, and the server reports per-feature
// gating rather than one flag. Anything named here was asked for and not
// answered, which is different from being asked for and found empty.
func (e *scaEngine) recordTier(meta vdb.CliResponseMeta) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if meta.Tier != "" {
		e.tier = meta.Tier
	}
	for feature, gated := range meta.TierGated {
		if !gated {
			continue
		}
		if e.gated == nil {
			e.gated = map[string]bool{}
		}
		e.gated[feature] = true
	}
}

// Gated reports whether the server withheld a feature for subscription reasons.
func (e *scaEngine) Gated(feature string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gated[feature]
}

// Tier is the subscription tier the server last reported.
func (e *scaEngine) Tier() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tier != "" {
		return e.tier
	}
	return e.plan
}

// gatedFeatures lists the withheld features, for logging.
func (e *scaEngine) gatedFeatures() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.gated))
	for feature := range e.gated {
		out = append(out, feature)
	}
	sort.Strings(out)
	return out
}
