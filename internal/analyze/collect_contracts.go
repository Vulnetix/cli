package analyze

// Cross-repo contract edges: the routes, topics, images and workflows that link one
// repository to another.
//
// Packages alone make a dependency graph. What makes an *org* graph is that the web app
// calls a route the API serves, the worker consumes a topic the API publishes, and both
// deploy from an image the platform repo builds — none of which is a package dependency and
// none of which appears anywhere in a lockfile.
//
// The scanner still never reads another repository. It writes down what this one provides
// and what it consumes, as a normalised key, and the server forms the edge where a consumer
// meets a provider. The normalisation is the entire game: two repos that spell the same
// route differently will never meet, so `/users/:id` and `/users/{userId}` both have to come
// out as `GET /users/{param}` or the edge does not exist.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/scan"
	"gopkg.in/yaml.v3"
)

// Health and observability endpoints are excluded. Every service has `/health`; if we
// published it, every repo would appear to consume every other repo's health check, and the
// org graph would be an N×M mesh of edges that mean nothing. GitNexus hit exactly this and
// had to filter it out after the fact.
var noiseRoutes = map[string]bool{
	"/health": true, "/healthz": true, "/healthcheck": true, "/health-check": true,
	"/ready": true, "/readyz": true, "/live": true, "/livez": true,
	"/metrics": true, "/ping": true, "/status": true, "/": true, "": true,
}

var (
	// Go: chi/gin/echo/mux all spell it `r.Get("/path", ...)` or `r.HandleFunc("/path", ...)`.
	goRoute = regexp.MustCompile(`(?m)\.(Get|Post|Put|Patch|Delete|Head|Options|Handle|HandleFunc)\(\s*"([^"]+)"`)

	// Express / Fastify / Koa.
	jsRoute = regexp.MustCompile(`(?m)\.(get|post|put|patch|delete|all)\(\s*['"` + "`" + `]([^'"` + "`" + `]+)`)

	// FastAPI / Flask decorators.
	pyRoute = regexp.MustCompile(`(?m)@\w+\.(get|post|put|patch|delete|route)\(\s*['"]([^'"]+)`)

	// Spring.
	javaRoute = regexp.MustCompile(`(?m)@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?"([^"]+)"`)

	// Path parameters, in every dialect anyone uses.
	pathParam = regexp.MustCompile(`(:[A-Za-z_][\w]*)|(\{[^}]*\})|(<[^>]*>)|(\*)`)

	// Publish/subscribe, across the common client libraries.
	publishCall   = regexp.MustCompile(`(?i)\b(?:publish|produce|send_message|sendmessage|emit)\s*\(\s*['"]([\w.\-/]+)['"]`)
	subscribeCall = regexp.MustCompile(`(?i)\b(?:subscribe|consume|receive_message|receivemessage|on)\s*\(\s*['"]([\w.\-/]+)['"]`)

	// Dockerfile variable expansion for the subset that can affect FROM image references.
	dockerVariable = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

	terraformResource       = regexp.MustCompile(`(?m)\bresource\s+"([^"]+)"\s+"([^"]+)"`)
	terraformProviderSource = regexp.MustCompile(`(?m)\bsource\s*=\s*"([^"]+/[^"]+)"`)
	terraformModuleSource   = regexp.MustCompile(`(?m)\bmodule\s+"([^"]+)"\s*\{[^}]*?\bsource\s*=\s*"([^"]+)"`)
)

type contractStats struct {
	edges []CrossRepoEdge
	nodes []Node
}

func collectContracts(b *Builder, root string, files *fileStats, deps *depStats, target Target) *contractStats {
	st := &contractStats{}
	seen := map[string]bool{}

	add := func(e CrossRepoEdge, node Node) {
		if seen[e.ID] {
			return
		}
		seen[e.ID] = true
		st.edges = append(st.edges, e)
		st.nodes = append(st.nodes, node)
	}

	// The package keys belong here too. They were being built in the graph assembler, which
	// meant the "cross-repo join keys" metric counted the routes and the images and quietly
	// omitted the 95 packages — a number that was wrong in the reassuring direction.
	if deps != nil {
		for _, d := range deps.deps {
			id := "dependency:" + d.Purl
			add(CrossRepoEdge{
				ID:          "xr-consumes-" + safeID(d.Purl),
				LocalNodeID: id,
				JoinKind:    "package",
				JoinKey:     purlWithoutVersion(d.Purl),
				Role:        "consumes",
				Confidence:  1,
			}, Node{
				ID: id, Kind: "dependency", Name: purlName(d.Purl), Purl: d.Purl,
				Properties: map[string]any{"ecosystem": d.Ecosystem, "scope": d.Scope},
			})
		}
		for _, p := range deps.provides {
			add(p, Node{
				ID: p.LocalNodeID, Kind: "package",
				Name: strings.TrimPrefix(p.LocalNodeID, "package:"), Exported: true,
			})
		}
	}

	if files != nil {
		for _, f := range files.files {
			// A mock server in a test does not serve an org route, and a topic name in a fixture
			// is not a topic anybody publishes. Test files stand up HTTP handlers constantly; if
			// we read them, every repository with an httptest server would appear to provide
			// whatever paths its tests happen to use.
			if isTestPath(f.Path) {
				continue
			}

			body, err := os.ReadFile(filepath.Join(root, f.Path))
			if err != nil {
				continue
			}

			// Comments are stripped before anything is matched. A doc comment that says
			// `r.Get("/v1/users", ...)` to explain how a router works is not a route anybody
			// serves — and this file, which documents exactly that, was publishing itself as an
			// HTTP provider until the comments came out.
			src := stripComments(string(body), f.Language)

			// Only a file that actually stands up a server can *provide* a route. Without this
			// gate, a client that calls `.Get("/v1/users")` and a server that serves it look
			// identical to a regex, and we publish the caller as the provider — which is not a
			// low-confidence edge, it is a backwards one. A wrong direction is worse than a
			// missing edge, because the org graph would show the dependency inverted.
			if !servesHTTP(src, f.Language) {
				continue
			}

			for _, r := range extractRoutes(src, f.Language) {
				key := normaliseRoute(r.method, r.path)
				if key == "" {
					continue
				}
				id := "route:" + key
				add(CrossRepoEdge{
					ID:          "xr-provides-" + safeID(key),
					LocalNodeID: id,
					JoinKind:    "http_route",
					JoinKey:     key,
					Role:        "provides",
					Confidence:  0.8, // a route matched by pattern, not by understanding the framework
					Properties:  map[string]any{"path": f.Path},
				}, Node{ID: id, Kind: "route", Name: key, Path: f.Path, Exported: true})
			}

			for _, topic := range publishCall.FindAllStringSubmatch(src, -1) {
				t := strings.TrimSpace(topic[1])
				if t == "" || len(t) < 3 {
					continue
				}
				id := "topic:" + t
				add(CrossRepoEdge{
					ID:          "xr-provides-topic-" + safeID(t),
					LocalNodeID: id,
					JoinKind:    "topic",
					JoinKey:     t,
					Role:        "provides",
					Confidence:  0.7,
					Properties:  map[string]any{"path": f.Path},
				}, Node{ID: id, Kind: "topic", Name: t, Path: f.Path})
			}

			for _, topic := range subscribeCall.FindAllStringSubmatch(src, -1) {
				t := strings.TrimSpace(topic[1])
				if t == "" || len(t) < 3 {
					continue
				}
				id := "topic:" + t
				add(CrossRepoEdge{
					ID:          "xr-consumes-topic-" + safeID(t),
					LocalNodeID: id,
					JoinKind:    "topic",
					JoinKey:     t,
					Role:        "consumes",
					Confidence:  0.7,
					Properties:  map[string]any{"path": f.Path},
				}, Node{ID: id, Kind: "topic", Name: t, Path: f.Path})
			}
		}
	}

	collectImages(root, add)
	collectInfrastructure(root, add)
	collectRegistries(root, add)
	collectWorkflows(root, target, add)

	emitContractMetrics(b, st)

	return st
}

type route struct {
	method string
	path   string
}

// serverSignals are the constructions that mean "this file serves HTTP". A file that has one
// of these and declares a route is a provider. A file that has none is, at best, a client —
// and a client's `.Get("/v1/users")` is a *consumes*, not a *provides*.
//
// We do not publish the consumes side for routes. Inferring "this string is a URL path being
// called" from a regex is guesswork, and a wrong consumes edge invents a dependency that does
// not exist. Providers we can identify; callers we cannot, yet. The metric says so rather
// than filling the gap with confident nonsense.
var serverSignals = map[string][]string{
	"go": {
		"chi.NewRouter", "chi.NewMux", "gin.Default", "gin.New", "echo.New",
		"mux.NewRouter", "http.HandleFunc", "http.ListenAndServe", "fiber.New",
	},
	"javascript": {"express(", "fastify(", "new Koa(", "Router("},
	"typescript": {"express(", "fastify(", "new Koa(", "Router("},
	"python":     {"FastAPI(", "Flask(", "APIRouter(", "Blueprint("},
	"java":       {"@RestController", "@Controller", "@RequestMapping"},
	"kotlin":     {"@RestController", "@Controller", "@RequestMapping"},
	"ruby":       {"Rails.application.routes", "Sinatra::Base"},
}

var (
	lineComment  = regexp.MustCompile(`(?m)//.*$`)
	hashComment  = regexp.MustCompile(`(?m)#.*$`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// stripComments removes comments so that an example in a doc comment is not mistaken for a
// route somebody serves.
//
// This is a lexical approximation, not a parser: a `//` inside a string literal (a URL, say)
// will take the rest of that line with it. That trade is deliberate. Losing a route because
// its line contained a URL is a missing edge; publishing every framework example in every
// doc comment is a graph full of endpoints nobody serves. Of the two, the false positive is
// the one that makes the org graph useless.
func stripComments(src, language string) string {
	switch language {
	case "python", "ruby", "bash", "yaml":
		return hashComment.ReplaceAllString(src, "")
	default:
		src = blockComment.ReplaceAllString(src, "")

		return lineComment.ReplaceAllString(src, "")
	}
}

// isTestPath reports whether a file is test code, in any of the conventions people actually
// use. Test code is excluded from contract extraction — not from the rest of the report,
// where it is perfectly real code worth counting.
func isTestPath(p string) bool {
	base := strings.ToLower(filepath.Base(p))

	switch {
	case strings.HasSuffix(base, "_test.go"),
		strings.HasSuffix(base, ".test.ts"), strings.HasSuffix(base, ".test.js"),
		strings.HasSuffix(base, ".spec.ts"), strings.HasSuffix(base, ".spec.js"),
		strings.HasPrefix(base, "test_"), strings.HasSuffix(base, "_test.py"),
		strings.HasSuffix(base, "_spec.rb"), strings.HasSuffix(base, "test.java"):

		return true
	}

	for _, seg := range strings.Split(strings.ToLower(filepath.ToSlash(p)), "/") {
		switch seg {
		case "test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures", "e2e":
			return true
		}
	}

	return false
}

func servesHTTP(src, language string) bool {
	for _, sig := range serverSignals[language] {
		if strings.Contains(src, sig) {
			return true
		}
	}

	return false
}

func extractRoutes(src, language string) []route {
	var re *regexp.Regexp
	switch language {
	case "go":
		re = goRoute
	case "javascript", "typescript", "tsx":
		re = jsRoute
	case "python":
		re = pyRoute
	case "java", "kotlin":
		re = javaRoute
	default:
		return nil
	}

	var out []route
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		p := m[2]
		if !strings.HasPrefix(p, "/") {
			continue
		}
		out = append(out, route{method: strings.ToUpper(m[1]), path: p})
	}

	return out
}

// normaliseRoute is what makes a cross-repo route edge possible at all.
//
// The server that declares `/users/:id` and the client that calls `/users/{userId}` are
// talking about the same endpoint, and they will only ever meet in the org graph if both
// sides collapse to the same string. Path parameters carry no meaning for matching — only
// their position does — so every dialect of them becomes `{param}`.
//
// Returns "" for routes that are pure noise.
func normaliseRoute(method, p string) string {
	p = strings.TrimSpace(p)
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}

	if noiseRoutes[strings.ToLower(p)] {
		return ""
	}

	norm := pathParam.ReplaceAllString(p, "{param}")

	// A route that is nothing but parameters (`/{param}`, `/{param}/{param}`) matches
	// everything and therefore identifies nothing. Publishing it would link every repo that
	// has a catch-all to every other one.
	stripped := strings.ReplaceAll(norm, "{param}", "")
	stripped = strings.ReplaceAll(stripped, "/", "")
	if stripped == "" {
		return ""
	}

	if method == "HANDLE" || method == "HANDLEFUNC" || method == "ALL" || method == "ROUTE" || method == "REQUEST" {
		method = "ANY"
	}

	return method + " " + norm
}

// collectImages reads Dockerfiles and compose files. A repo that runs `FROM ghcr.io/acme/base`
// consumes an image; if another repo in the org builds it, that is an edge — and it is one of
// the most load-bearing edges in an org graph, because a base-image change reaches everything.
func collectImages(root string, add func(CrossRepoEdge, Node)) {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}

			return nil
		}

		name := strings.ToLower(d.Name())
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)

		switch {
		case name == "dockerfile" || strings.HasPrefix(name, "dockerfile.") ||
			name == "containerfile" || strings.HasPrefix(name, "containerfile."):

			body, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}

			stages := map[string]bool{}
			refs := dockerfileFromRefs(string(body))
			for _, ref := range refs {
				img := normaliseImage(ref.Image)
				// Build stages are internal to the file. `FROM builder` is not a dependency on
				// anybody's image, and publishing it would create an edge to a repo called "builder".
				if img == "" || stages[strings.ToLower(ref.Image)] {
					if ref.Stage != "" {
						stages[strings.ToLower(ref.Stage)] = true
					}
					continue
				}
				id := "container_image:" + img
				add(CrossRepoEdge{
					ID:          "xr-consumes-image-" + safeID(img),
					LocalNodeID: id,
					JoinKind:    "container_image",
					JoinKey:     img,
					Role:        "consumes",
					Confidence:  1,
					Properties:  map[string]any{"path": rel},
				}, Node{ID: id, Kind: "container_image", Name: img, Path: rel})
				addContainerRegistry(img, rel, add)
				if ref.Stage != "" {
					stages[strings.ToLower(ref.Stage)] = true
				}
			}

		case name == "docker-compose.yml" || name == "docker-compose.yaml" ||
			name == "compose.yml" || name == "compose.yaml":

			body, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			var doc struct {
				Services map[string]struct {
					Image string `yaml:"image"`
				} `yaml:"services"`
			}
			if yaml.Unmarshal(body, &doc) != nil {
				return nil
			}
			for _, svc := range doc.Services {
				img := normaliseImage(svc.Image)
				if img == "" {
					continue
				}
				id := "container_image:" + img
				add(CrossRepoEdge{
					ID:          "xr-consumes-image-" + safeID(img),
					LocalNodeID: id,
					JoinKind:    "container_image",
					JoinKey:     img,
					Role:        "consumes",
					Confidence:  1,
					Properties:  map[string]any{"path": rel},
				}, Node{ID: id, Kind: "container_image", Name: img, Path: rel})
				addContainerRegistry(img, rel, add)
			}
		}

		return nil
	})
}

type dockerFromRef struct {
	Image string
	Stage string
}

func dockerfileFromRefs(src string) []dockerFromRef {
	args := map[string]string{}
	out := []dockerFromRef{}

	for _, line := range dockerLogicalLines(src) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		keyword := fields[0]
		rest := strings.TrimSpace(strings.TrimPrefix(line, keyword))
		switch strings.ToUpper(keyword) {
		case "ARG":
			parseDockerArg(rest, args)
		case "FROM":
			ref := parseDockerFrom(rest, args)
			if ref.Image != "" {
				out = append(out, ref)
			}
		}
	}

	return out
}

func dockerLogicalLines(src string) []string {
	var lines []string
	var current strings.Builder

	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, "\r\t ")
		continued := strings.HasSuffix(line, "\\")
		if continued {
			line = strings.TrimRight(strings.TrimSuffix(line, "\\"), "\t ")
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(line)
		if continued {
			continue
		}
		lines = append(lines, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}

	return lines
}

func parseDockerArg(rest string, args map[string]string) {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return
	}
	name, value, hasValue := strings.Cut(fields[0], "=")
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	if !hasValue {
		if _, ok := args[name]; !ok {
			args[name] = ""
		}
		return
	}
	args[name] = interpolateDockerValue(strings.Trim(value, `"'`), args)
}

func parseDockerFrom(rest string, args map[string]string) dockerFromRef {
	fields := strings.Fields(rest)
	i := 0
	for i < len(fields) && strings.HasPrefix(fields[i], "--") {
		if !strings.Contains(fields[i], "=") {
			i++
		}
		i++
	}
	if i >= len(fields) {
		return dockerFromRef{}
	}

	ref := dockerFromRef{Image: interpolateDockerValue(strings.Trim(fields[i], `"'`), args)}
	for j := i + 1; j+1 < len(fields); j++ {
		if strings.EqualFold(fields[j], "AS") {
			ref.Stage = strings.Trim(fields[j+1], `"'`)
			break
		}
	}

	return ref
}

func interpolateDockerValue(value string, args map[string]string) string {
	return dockerVariable.ReplaceAllStringFunc(value, func(match string) string {
		parts := dockerVariable.FindStringSubmatch(match)
		if len(parts) == 0 {
			return match
		}

		name := parts[1]
		if name == "" {
			name = parts[4]
		}
		value, ok := args[name]
		if parts[2] == ":-" || parts[2] == "-" {
			if !ok || value == "" {
				return parts[3]
			}
		}
		if parts[2] == ":+" || parts[2] == "+" {
			if ok && value != "" {
				return parts[3]
			}
			return ""
		}
		if !ok {
			return match
		}

		return value
	})
}

func addContainerRegistry(image, rel string, add func(CrossRepoEdge, Node)) {
	registry := imageRegistry(image)
	if registry == "" {
		return
	}
	id := "container_registry:" + registry
	add(CrossRepoEdge{
		ID:          "xr-consumes-container-registry-" + safeID(registry),
		LocalNodeID: id,
		JoinKind:    "container_registry",
		JoinKey:     registry,
		Role:        "consumes",
		Confidence:  1,
		Properties:  map[string]any{"path": rel},
	}, Node{ID: id, Kind: "container_registry", Name: registry, Path: rel})
}

func imageRegistry(image string) string {
	first := strings.Split(image, "/")[0]
	if first == "" || !strings.ContainsAny(first, ".:") {
		return "docker.io"
	}
	return strings.ToLower(first)
}

// normaliseImage strips the tag and digest. `acme/api:1.2.3` and `acme/api:1.3.0` are the
// same image from the same repository; an org graph that only linked exact tags would show
// almost no edges, and the ones it showed would be an accident of who deployed last.
func normaliseImage(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "-") || strings.Contains(ref, "$") || strings.Contains(ref, "${") {
		// A templated image reference names nothing until it is expanded, and we cannot expand it.
		return ""
	}
	if i := strings.Index(ref, "@"); i > 0 {
		ref = ref[:i]
	}
	// A colon after the last slash is a tag. A colon before it is a registry port.
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	if ref == "scratch" {
		return ""
	}

	return strings.ToLower(ref)
}

func collectInfrastructure(root string, add func(CrossRepoEdge, Node)) {
	tfIdentities := collectTerraformIdentities(root)
	declaredTerraform := map[string]bool{}
	knownTerraformPrimary := map[string]bool{}

	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		base := strings.ToLower(filepath.Base(p))
		ext := strings.ToLower(filepath.Ext(p))

		switch {
		case ext == ".tf":
			collectTerraform(p, rel, tfIdentities, declaredTerraform, knownTerraformPrimary, add)
		case base == "chart.yaml" || base == "chart.yml":
			collectHelmChart(p, rel, add)
		case ext == ".yaml" || ext == ".yml" || ext == ".json":
			collectYAMLInfrastructure(p, rel, add)
		}
		return nil
	})

	for _, identity := range tfIdentities.stateOnlyResources(declaredTerraform) {
		addTerraformStateResource(identity, knownTerraformPrimary, add)
	}
	for _, output := range tfIdentities.outputOnlyIdentifiers(knownTerraformPrimary) {
		addTerraformOutputResource(output, knownTerraformPrimary, add)
	}
}

func collectTerraform(abs, rel string, identities *terraformIdentityIndex, declared, knownPrimary map[string]bool, add func(CrossRepoEdge, Node)) {
	body, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	src := string(body)
	for _, m := range terraformResource.FindAllStringSubmatch(src, -1) {
		typ, name := m[1], m[2]
		provider := strings.SplitN(typ, "_", 2)[0]
		key := "terraform:" + typ + ":" + name
		id := "iac_resource:" + key
		props := map[string]any{"path": rel, "platform": "terraform", "resourceType": typ, "provider": provider}
		joinKey := key
		qualifiedName := ""
		address := typ + "." + name
		declared[address] = true
		if identity, ok := identities.lookup(address); ok {
			joinKey = terraformIdentityJoinKey(key, identity.Primary)
			qualifiedName = identity.Primary
			mergeTerraformIdentityProperties(props, identity.SourcePath, identity.Identifiers, identity.Metadata)
			if identity.Primary != "" {
				knownPrimary[identity.Primary] = true
			}
		}
		add(CrossRepoEdge{
			ID:          "xr-provides-iac-" + safeID(key),
			LocalNodeID: id,
			JoinKind:    "iac_resource",
			JoinKey:     joinKey,
			Role:        "provides",
			Confidence:  1,
			Properties:  props,
		}, Node{ID: id, Kind: "iac_resource", Name: typ + "." + name, QualifiedName: qualifiedName, Path: rel, Properties: props})
		if provider != "" {
			providerKey := "terraform:" + provider
			addRegistryLike("iac_provider", providerKey, rel, "consumes", 0.9, add)
		}
	}
	for _, m := range terraformProviderSource.FindAllStringSubmatch(src, -1) {
		source := strings.TrimSpace(m[1])
		if source == "" {
			continue
		}
		host := terraformRegistryHost(source)
		if host != "" {
			addRegistryLike("terraform_registry", host, rel, "consumes", 1, add)
		}
		addRegistryLike("terraform_provider", normaliseTerraformSource(source), rel, "consumes", 1, add)
	}
	for _, m := range terraformModuleSource.FindAllStringSubmatch(src, -1) {
		modName, source := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		if source == "" || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			continue
		}
		key := normaliseTerraformSource(source)
		id := "terraform_module:" + key
		add(CrossRepoEdge{
			ID:          "xr-consumes-terraform-module-" + safeID(key+"-"+modName),
			LocalNodeID: id,
			JoinKind:    "terraform_module",
			JoinKey:     key,
			Role:        "consumes",
			Confidence:  0.9,
			Properties:  map[string]any{"path": rel, "module": modName},
		}, Node{ID: id, Kind: "terraform_module", Name: key, Path: rel})
		if host := terraformRegistryHost(source); host != "" {
			addRegistryLike("terraform_registry", host, rel, "consumes", 1, add)
		}
	}
}

func addTerraformStateResource(identity terraformResourceIdentity, knownPrimary map[string]bool, add func(CrossRepoEdge, Node)) {
	if identity.Address == "" {
		return
	}
	if identity.Primary != "" && knownPrimary[identity.Primary] {
		return
	}
	key := "terraform:" + identity.Address
	id := "iac_resource:" + key
	props := map[string]any{
		"path":         identity.SourcePath,
		"platform":     "terraform",
		"resourceType": identity.Type,
		"stateAddress": identity.Address,
		"stateOnly":    true,
	}
	if provider := terraformProviderShortName(identity.Type, identity.Provider); provider != "" {
		props["provider"] = provider
	}
	mergeTerraformIdentityProperties(props, identity.SourcePath, identity.Identifiers, identity.Metadata)
	if identity.Primary != "" {
		knownPrimary[identity.Primary] = true
	}
	joinKey := terraformIdentityJoinKey(key, identity.Primary)
	add(CrossRepoEdge{
		ID:          "xr-provides-iac-state-" + safeID(key),
		LocalNodeID: id,
		JoinKind:    "iac_resource",
		JoinKey:     joinKey,
		Role:        "provides",
		Confidence:  0.95,
		Properties:  props,
	}, Node{ID: id, Kind: "iac_resource", Name: identity.Address, QualifiedName: identity.Primary, Path: identity.SourcePath, Properties: props})
}

func addTerraformOutputResource(output terraformOutputIdentity, knownPrimary map[string]bool, add func(CrossRepoEdge, Node)) {
	if output.Primary == "" || knownPrimary[output.Primary] {
		return
	}
	knownPrimary[output.Primary] = true
	key := terraformOutputNodeKey(output)
	id := "iac_resource:" + key
	props := map[string]any{
		"path":         output.SourcePath,
		"platform":     "terraform",
		"resourceType": "terraform_output",
		"outputName":   output.Name,
		"outputOnly":   true,
	}
	mergeTerraformIdentityProperties(props, output.SourcePath, output.Identifiers, output.Metadata)
	add(CrossRepoEdge{
		ID:          "xr-provides-iac-output-" + safeID(output.Name+"-"+output.Primary),
		LocalNodeID: id,
		JoinKind:    "iac_resource",
		JoinKey:     output.Primary,
		Role:        "provides",
		Confidence:  0.8,
		Properties:  props,
	}, Node{ID: id, Kind: "iac_resource", Name: output.Name, QualifiedName: output.Primary, Path: output.SourcePath, Properties: props})
}

func terraformOutputNodeKey(output terraformOutputIdentity) string {
	if output.Primary == "" {
		return "terraform_output:" + output.Name
	}

	return "terraform_output:" + output.Name + ":" + safeID(output.Primary)
}

func terraformIdentityJoinKey(fallback, primary string) string {
	if primary == "" {
		return fallback
	}

	return primary
}

func mergeTerraformIdentityProperties(props map[string]any, sourcePath string, identifiers map[string]string, metadata map[string]string) {
	if len(identifiers) > 0 {
		props["cloudIdentifiers"] = identifiers
		if primary := primaryCloudIdentifier(identifiers); primary != "" {
			props["cloudIdentifier"] = primary
		}
	}
	if sourcePath != "" {
		props["identifierSource"] = sourcePath
	}
	for key, value := range metadata {
		if value == "" {
			continue
		}
		props[key] = value
	}
}

func terraformProviderShortName(resourceType, provider string) string {
	if resourceType != "" {
		return strings.SplitN(resourceType, "_", 2)[0]
	}
	provider = strings.TrimSuffix(provider, `"]`)
	if i := strings.LastIndex(provider, "/"); i >= 0 {
		return provider[i+1:]
	}

	return provider
}

func collectHelmChart(abs, rel string, add func(CrossRepoEdge, Node)) {
	body, err := os.ReadFile(abs)
	if err != nil {
		return
	}
	var chart struct {
		Name         string `yaml:"name"`
		APIVersion   string `yaml:"apiVersion"`
		Dependencies []struct {
			Name       string `yaml:"name"`
			Version    string `yaml:"version"`
			Repository string `yaml:"repository"`
		} `yaml:"dependencies"`
	}
	if yaml.Unmarshal(body, &chart) != nil {
		return
	}
	if chart.Name != "" {
		key := "helm:" + chart.Name
		id := "helm_chart:" + key
		add(CrossRepoEdge{
			ID:          "xr-provides-helm-chart-" + safeID(key),
			LocalNodeID: id,
			JoinKind:    "helm_chart",
			JoinKey:     key,
			Role:        "provides",
			Confidence:  1,
			Properties:  map[string]any{"path": rel, "apiVersion": chart.APIVersion},
		}, Node{ID: id, Kind: "helm_chart", Name: chart.Name, Path: rel, Exported: true})
	}
	for _, dep := range chart.Dependencies {
		if dep.Name == "" {
			continue
		}
		key := "helm:" + dep.Name
		id := "helm_chart:" + key
		add(CrossRepoEdge{
			ID:          "xr-consumes-helm-chart-" + safeID(key),
			LocalNodeID: id,
			JoinKind:    "helm_chart",
			JoinKey:     key,
			Role:        "consumes",
			Confidence:  1,
			Properties:  map[string]any{"path": rel, "repository": dep.Repository, "version": dep.Version},
		}, Node{ID: id, Kind: "helm_chart", Name: dep.Name, Path: rel})
		if dep.Repository != "" {
			addRegistryLike("helm_registry", dep.Repository, rel, "consumes", 1, add)
		}
	}
}

func collectYAMLInfrastructure(abs, rel string, add func(CrossRepoEdge, Node)) {
	body, err := os.ReadFile(abs)
	if err != nil {
		return
	}

	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil || len(doc) == 0 {
			break
		}

		if resources, ok := mapAny(doc["Resources"]); ok {
			platform := "cloudformation"
			if transform := fmt.Sprint(doc["Transform"]); strings.Contains(transform, "AWS::Serverless") {
				platform = "aws-sam"
			}
			for logicalID, raw := range resources {
				res, ok := mapAny(raw)
				if !ok {
					continue
				}
				typ, _ := res["Type"].(string)
				if typ == "" {
					continue
				}
				key := platform + ":" + typ + ":" + logicalID
				id := "iac_resource:" + key
				props := map[string]any{"path": rel, "platform": platform, "resourceType": typ}
				add(CrossRepoEdge{
					ID:          "xr-provides-iac-" + safeID(key),
					LocalNodeID: id,
					JoinKind:    "iac_resource",
					JoinKey:     key,
					Role:        "provides",
					Confidence:  1,
					Properties:  props,
				}, Node{ID: id, Kind: "iac_resource", Name: logicalID, Path: rel, Properties: props})
			}
			continue
		}

		apiVersion, _ := doc["apiVersion"].(string)
		kind, _ := doc["kind"].(string)
		meta, _ := mapAny(doc["metadata"])
		name, _ := meta["name"].(string)
		if apiVersion != "" && kind != "" && name != "" {
			key := "kubernetes:" + kind + ":" + name
			id := "iac_resource:" + key
			props := map[string]any{"path": rel, "platform": "kubernetes", "resourceType": kind, "apiVersion": apiVersion}
			add(CrossRepoEdge{
				ID:          "xr-provides-iac-" + safeID(key),
				LocalNodeID: id,
				JoinKind:    "iac_resource",
				JoinKey:     key,
				Role:        "provides",
				Confidence:  1,
				Properties:  props,
			}, Node{ID: id, Kind: "iac_resource", Name: kind + "/" + name, Path: rel, Properties: props})
			collectKubernetesImages(doc, rel, add)
		}
	}
}

func collectKubernetesImages(doc map[string]any, rel string, add func(CrossRepoEdge, Node)) {
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if image, ok := x["image"].(string); ok {
				img := normaliseImage(image)
				if img != "" {
					id := "container_image:" + img
					add(CrossRepoEdge{
						ID:          "xr-consumes-image-" + safeID(img),
						LocalNodeID: id,
						JoinKind:    "container_image",
						JoinKey:     img,
						Role:        "consumes",
						Confidence:  1,
						Properties:  map[string]any{"path": rel},
					}, Node{ID: id, Kind: "container_image", Name: img, Path: rel})
					addContainerRegistry(img, rel, add)
				}
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(doc)
}

func collectRegistries(root string, add func(CrossRepoEdge, Node)) {
	files, err := scan.WalkForScanFiles(scan.WalkOptions{RootPath: root, MaxDepth: 20})
	if err != nil {
		return
	}
	for _, ep := range scan.SummarizeRegistryConfigs(files) {
		if ep.URL == "" {
			continue
		}
		kind := ep.Ecosystem + "_registry"
		if ep.Ecosystem == "" {
			kind = "package_registry"
		}
		addRegistryLike(kind, ep.URL, strings.TrimPrefix(ep.Source, "./"), "consumes", 1, add)
	}
}

func addRegistryLike(kind, key, rel, role string, confidence float64, add func(CrossRepoEdge, Node)) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	id := kind + ":" + key
	add(CrossRepoEdge{
		ID:          "xr-" + role + "-" + kind + "-" + safeID(key),
		LocalNodeID: id,
		JoinKind:    kind,
		JoinKey:     key,
		Role:        role,
		Confidence:  confidence,
		Properties:  map[string]any{"path": rel},
	}, Node{ID: id, Kind: kind, Name: key, Path: rel})
}

func terraformRegistryHost(source string) string {
	source = strings.TrimSpace(source)
	if source == "" || strings.Contains(source, "://") {
		return ""
	}
	parts := strings.Split(source, "/")
	if len(parts) >= 3 && strings.Contains(parts[0], ".") {
		return strings.ToLower(parts[0])
	}
	return "registry.terraform.io"
}

func normaliseTerraformSource(source string) string {
	source = strings.TrimSpace(strings.SplitN(source, "?", 2)[0])
	source = strings.TrimSuffix(source, ".git")
	if strings.Contains(source, "://") {
		source = strings.TrimPrefix(source, "git::")
	}
	return strings.ToLower(source)
}

func mapAny(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// collectWorkflows reads .github/workflows. A reusable workflow this repo *defines* is
// provided; one it `uses:` is consumed. Platform teams live in these edges — a change to a
// shared release workflow reaches every repo that calls it, and nothing else in the graph
// would show that.
func collectWorkflows(root string, target Target, add func(CrossRepoEdge, Node)) {
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		p := filepath.Join(dir, name)
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			continue
		}
		rel := ".github/workflows/" + name

		var doc struct {
			On map[string]any `yaml:"on"`
		}
		_ = yaml.Unmarshal(body, &doc)

		if _, reusable := doc.On["workflow_call"]; reusable {
			key := workflowKey(target, rel)
			if key != "" {
				id := "workflow:" + key
				add(CrossRepoEdge{
					ID:          "xr-provides-workflow-" + safeID(key),
					LocalNodeID: id,
					JoinKind:    "workflow",
					JoinKey:     key,
					Role:        "provides",
					Confidence:  1,
					Properties:  map[string]any{"path": rel},
				}, Node{ID: id, Kind: "workflow", Name: name, Path: rel, Exported: true})
			}
		}

		// `uses:` to another repository's reusable workflow.
		sc := bufio.NewScanner(strings.NewReader(string(body)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "uses:") {
				continue
			}
			ref := strings.TrimSpace(strings.TrimPrefix(line, "uses:"))
			if !strings.Contains(ref, "/.github/workflows/") {
				continue
			}
			key := strings.SplitN(ref, "@", 2)[0]
			key = strings.Trim(key, `"'`)
			if key == "" {
				continue
			}
			id := "workflow:" + key
			add(CrossRepoEdge{
				ID:          "xr-consumes-workflow-" + safeID(key),
				LocalNodeID: id,
				JoinKind:    "workflow",
				JoinKey:     key,
				Role:        "consumes",
				Confidence:  1,
				Properties:  map[string]any{"path": rel},
			}, Node{ID: id, Kind: "workflow", Name: key, Path: rel})
		}
	}
}

// workflowKey is `owner/repo/.github/workflows/x.yml` — the exact string another repository
// writes in its `uses:`. Both sides have to produce the identical string or the edge does not
// form, so this is built from the repoId rather than guessed.
func workflowKey(target Target, rel string) string {
	parts := strings.Split(target.RepoID, "~")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return ""
	}

	return fmt.Sprintf("%s/%s/%s", parts[1], parts[2], rel)
}

func emitContractMetrics(b *Builder, st *contractStats) {
	byKind := map[string]map[string][]EvidenceRef{}

	for _, e := range st.edges {
		id := "xr-" + safeID(e.ID)
		ref := b.AddRecord(id, &GraphElementRecord{
			ID:        id,
			Type:      "graph_element",
			ElementID: e.ID,
			Element:   "cross_repo_edge",
		})
		if byKind[e.JoinKind] == nil {
			byKind[e.JoinKind] = map[string][]EvidenceRef{}
		}
		byKind[e.JoinKind][e.Role] = append(byKind[e.JoinKind][e.Role], ref)
	}

	all := []EvidenceRef{}
	for _, kind := range sortedKeys(byKind) {
		for _, role := range sortedKeys(byKind[kind]) {
			refs := byKind[kind][role]
			all = append(all, refs...)

			b.Count(Metric{
				ID:     fmt.Sprintf("graph.cross_repo.%s.%s", kind, role),
				Family: "graph",
				Name:   fmt.Sprintf("%s keys %s", strings.ReplaceAll(kind, "_", " "), role),
				Definition: fmt.Sprintf(
					"Normalised %s keys this repository %s. The scan never reads another repository — it publishes these keys, and an org edge forms where one repository's consumes meets another's provides.",
					strings.ReplaceAll(kind, "_", " "), role),
			}, refs)
		}
	}

	b.Count(Metric{
		ID: "graph.cross_repo.total", Family: "graph", Name: "Cross-repo join keys",
		Definition: "Every key this repository publishes for the org graph: packages, HTTP routes, topics, container images and reusable workflows, each as a provides or a consumes. Health-check endpoints are excluded — every service has one, and publishing them would link every repository to every other.",
	}, all)

	// The honest limitation. An HTTP route we serve, we can identify: the file stands up a
	// router. An HTTP route we *call*, we cannot — a string that looks like a path in a client
	// is a guess, and a wrong consumes edge invents a dependency that does not exist. So the
	// route half of the org graph is currently one-directional, and the report says so rather
	// than letting a reader assume the absence of an edge means the absence of a call.
	b.Diagnose(Diagnostic{
		Level: "note", Collector: "contracts", Caveat: true,
		Message: "HTTP routes are published as `provides` only. Routes this repository *calls* are not detected — identifying a client call by pattern would invent dependencies that do not exist — so a missing route edge does not mean nothing calls it.",
	})
}

var _ = sort.Strings
