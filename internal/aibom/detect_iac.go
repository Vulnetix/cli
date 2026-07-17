package aibom

import (
	"path"
	"regexp"
	"sort"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/Vulnetix/vdb-sca-match/parse"
	"github.com/vulnetix/cli/v3/internal/sast"
	yaml "gopkg.in/yaml.v3"
)

// detectIaC scans infrastructure-as-code files — Kubernetes manifests
// (including CRDs), docker-compose files and Dockerfiles — for the AI
// workloads they would produce: serving runtimes, agent platforms, vector
// databases, training/eval frameworks, model identities and model-artifact /
// dataset volumes.
//
// Detection follows the honest-not-clever contract: image patterns are a
// narrow allowlist (mirrored/private copies are documented false negatives),
// every extracted value is validated before it becomes a component, and
// anything that cannot be verified is either dropped (likely false positive)
// or reported with a confidence gap stating exactly what could not be
// verified and why. Secret references (valueFrom, env_file) are never
// resolved.
func (c *collector) detectIaC(input *sast.ScanInput) {
	if input == nil || c.cat.Infra == nil {
		return
	}
	if input.FileContents == nil {
		sast.LoadFileContents(input, maxSourceFileSize)
	}

	paths := make([]string, 0, len(input.FileSet))
	for p := range input.FileSet {
		paths = append(paths, p)
	}
	sort.Strings(paths) // deterministic evidence order

	c.evalModelFiles(paths)

	for _, p := range paths {
		content, ok := input.FileContents[p]
		if !ok || content == "" {
			continue
		}
		base := strings.ToLower(path.Base(p))
		switch {
		case isComposeFile(base):
			for _, w := range parse.ParseComposeWorkloads([]byte(content), p) {
				c.evalWorkload(&w)
			}
		case isDockerfileName(base):
			if w := parse.ParseDockerfileWorkload([]byte(content), p); w != nil {
				c.evalWorkload(w)
			}
		case base == "values.yaml" || base == "values.yml":
			// Helm values: only meaningful next to a Chart.yaml.
			dir := path.Dir(p)
			if input.FileSet[path.Join(dir, "Chart.yaml")] || input.FileSet[path.Join(dir, "Chart.yml")] {
				c.evalHelmValues(p, content)
			}
		case base == "kustomization.yaml" || base == "kustomization.yml":
			c.evalKustomization(p, content)
		case strings.HasSuffix(base, ".tf") || strings.HasSuffix(base, ".tofu"):
			c.evalTerraform(p, content)
		case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
			// Cheap sniff before decoding: a Kubernetes document carries
			// both apiVersion and kind. This also excludes CI configs,
			// Helm values files and arbitrary YAML.
			if !strings.Contains(content, "apiVersion") || !strings.Contains(content, "kind:") {
				continue
			}
			ws := parse.ParseKubernetesWorkloads([]byte(content), p)
			if len(ws) == 0 && strings.Contains(content, "{{") {
				// Helm template that defeats structural parsing: fall back
				// to a narrow regex for image lines, reported with an
				// explicit confidence gap.
				c.evalHelmTemplateFallback(p, content)
				continue
			}
			for _, w := range ws {
				c.evalWorkload(&w)
			}
		}
	}
}

func isComposeFile(base string) bool {
	if base == "compose.yml" || base == "compose.yaml" {
		return true
	}
	for _, prefix := range []string{"docker-compose", "podman-compose"} {
		if strings.HasPrefix(base, prefix) && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
			return true
		}
	}
	return false
}

func isDockerfileName(base string) bool {
	return strings.Contains(base, "dockerfile") || strings.Contains(base, "containerfile")
}

// ---- workload evaluation ---------------------------------------------------

// semverShapedTag accepts tags that can honestly be reported as a version:
// x.y, x.y.z, or x.y.z with a single pre-release/build suffix. CalVer-plus-
// variant tags like 24.05-py3 and multi-suffix build tags like
// 2.4.0-cuda12.1-cudnn9-runtime keep the raw tag but report a confidence gap
// instead of a fabricated version.
var semverShapedTag = regexp.MustCompile(`^v?(\d+\.\d+\.\d+([-+][A-Za-z0-9.]+)?|\d+\.\d+)$`)

func (c *collector) evalWorkload(w *parse.Workload) {
	infra := c.cat.Infra
	loc := w.SourceFile
	if w.Kind != "dockerfile" && w.Name != "" {
		loc = w.SourceFile + "#" + w.Name
	}

	// CRD kinds declared in the catalog (KServe InferenceService, Kubeflow
	// jobs, KubeRay resources) are themselves infrastructure evidence, and
	// may carry declared model/runtime fields.
	if w.Raw != nil {
		c.evalCRD(w, loc)
	}

	trainingSignal := false

	for i := range w.Containers {
		ct := &w.Containers[i]
		runtimeHit := c.evalContainerImage(ct, loc)
		if runtimeHit != nil && runtimeHit.def.Category == "training" {
			trainingSignal = true
		}

		// Environment: model identity from allowlisted env var values,
		// framework signals and remote-API service dependencies from env
		// var NAMES. Values of key-shaped names are never read.
		for _, env := range ct.Env {
			if infra.ModelEnvVars[env.Name] {
				if env.IsRef {
					c.infraGap(runtimeHit, "model env "+env.Name+" references a secret/configMap; value not readable from IaC")
				} else if looksTemplated(env.Value) {
					c.infraGap(runtimeHit, "model env "+env.Name+" is templated; value not resolvable from IaC")
				} else {
					c.addModel(env.Value, "", "", "", cdx.AIEvidence{
						Method: "iac", Category: "env", Locator: loc + "#env:" + env.Name,
						Snippet: env.Name + "=" + env.Value,
					})
				}
			}
			if sig, ok := infra.EnvSignals[env.Name]; ok {
				if sig.Category == "training" {
					trainingSignal = true
				}
				c.infraHitSignal(sig, cdx.AIEvidence{
					Method: "iac", Category: "env-name", Locator: loc, Snippet: env.Name,
				})
			}
			c.evalServiceEnvName(env.Name, loc)
		}

		// Args/command: model identity from allowlisted flags.
		c.evalModelArgs(append(append([]string{}, ct.Command...), ct.Args...), loc)

		// Volume mounts: model artifacts under allowlisted mount prefixes.
		for _, m := range ct.Mounts {
			if !mountPrefixMatch(infra.ModelMountPrefixes, m.MountPath) {
				continue
			}
			c.addDataFromMount(w, m, "model-artifact", loc)
		}
	}

	// Dataset volumes are only meaningful on training workloads — a bare
	// /data mount on a web app is not an AI dataset.
	if trainingSignal || c.workloadHasTrainingCRD(w) {
		for i := range w.Containers {
			for _, m := range w.Containers[i].Mounts {
				if infra.DatasetVolumeNames[m.Name] || mountPrefixMatch(infra.DatasetMountPrefixes, m.MountPath) {
					c.addDataFromMount(w, m, "dataset", loc)
				}
			}
		}
	}

	// Declared model annotations (vulnetix.com/model.* primary,
	// model.k8saibom.dev/* honored for interop).
	for key, value := range w.Annotations {
		for _, prefix := range infra.AnnotationPrefixes {
			if strings.HasPrefix(key, prefix) {
				c.addModel(value, "", "", "", cdx.AIEvidence{
					Method: "iac", Category: "annotation", Locator: loc,
					Snippet: key + "=" + value,
				})
				break
			}
		}
	}

	// GPU / accelerator resource requests and node selectors.
	c.evalAccelerators(w, loc)
}

// evalContainerImage matches the container image against the runtime
// allowlist and returns the hit (nil when no runtime matched).
func (c *collector) evalContainerImage(ct *parse.WorkloadContainer, loc string) *infraHit {
	if parse.ImagePlaceholder(ct.Image) {
		return nil // FP guard: $VAR / {{ }} / scratch / empty
	}
	ref := parse.SplitImageRef(ct.Image)
	if ref.Name == "" {
		return nil
	}
	for i := range c.cat.Infra.Runtimes {
		rt := &c.cat.Infra.Runtimes[i]
		for _, re := range rt.Images {
			if !re.MatchString(ref.Name) {
				continue
			}
			hit := c.infraHitRuntime(rt.Def, ref, cdx.AIEvidence{
				Method: "iac", Category: "image", Locator: loc, Snippet: ct.Image,
			})
			if ref.Digest != "" && !ref.DigestValid() {
				c.infraGap(hit, "image digest malformed: "+ref.Digest)
			}
			return hit
		}
	}
	return nil
}

// evalCRD reports catalog-declared CRD kinds and pulls their declared
// model/runtime fields with type-checked dot-path traversal.
func (c *collector) evalCRD(w *parse.Workload, loc string) {
	for i := range c.cat.Infra.CRDs {
		crd := &c.cat.Infra.CRDs[i]
		if w.Kind != crd.Kind || !strings.HasPrefix(w.APIVersion, crd.APIVersionPrefix) {
			continue
		}
		hit := c.infraHitCRD(*crd, cdx.AIEvidence{
			Method: "iac", Category: "crd", Locator: loc,
			Snippet: w.APIVersion + "/" + w.Kind,
		})
		for _, f := range crd.Fields {
			value, ok := parse.FieldAt(w.Raw, f.Path)
			if !ok {
				if fieldPresentNonString(w.Raw, f.Path) {
					c.infraGap(hit, "field "+f.Path+" present but not a string")
				}
				continue
			}
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			switch f.As {
			case "model":
				c.evalStorageURI(value, hit, loc, f.Path)
			case "runtime":
				hit.runtime = value
				hit.evidenceAdd(cdx.AIEvidence{Method: "iac", Category: "crd-field", Locator: loc, Snippet: f.Path + "=" + value})
			case "runtime_version":
				if hit.version == "" {
					hit.version = value
				}
			case "runtime_ref", "service_account":
				hit.evidenceAdd(cdx.AIEvidence{Method: "iac", Category: "crd-field", Locator: loc, Snippet: f.Path + "=" + value})
			}
		}
		return
	}
}

// storageURISchemes are the model-artifact URI schemes we recognize on
// declared CRD fields (KServe storageUri and friends).
var storageURISchemes = map[string]bool{
	"gs": true, "s3": true, "hf": true, "pvc": true, "oci": true, "https": true, "http": true,
}

func (c *collector) evalStorageURI(uri string, hit *infraHit, loc, fieldPath string) {
	if looksTemplated(uri) {
		c.infraGap(hit, "field "+fieldPath+" is templated; value not resolvable from IaC")
		return
	}
	scheme, _, found := strings.Cut(uri, "://")
	data := &dataHit{name: uri, kind: "model-artifact", source: "uri"}
	if !found || !storageURISchemes[strings.ToLower(scheme)] {
		data.gap = true
		data.gapReason = "storageUri scheme unrecognized: " + uri
	}
	c.addData(data, cdx.AIEvidence{Method: "iac", Category: "crd-field", Locator: loc, Snippet: fieldPath + "=" + uri})
	c.addModel(uri, "", "", "", cdx.AIEvidence{
		Method: "iac", Category: "crd-field", Locator: loc, Snippet: fieldPath + "=" + uri,
	})
}

// evalServiceEnvName surfaces remote AI API dependencies (OPENAI_API_KEY,
// ANTHROPIC_API_KEY, ...) declared on workload containers, reusing the
// existing service-tool catalog. Only type:"service" entries participate —
// a coding-agent env var inside a manifest is not evidence the agent runs
// there.
func (c *collector) evalServiceEnvName(name, loc string) {
	for i := range c.cat.Tools {
		t := &c.cat.Tools[i]
		if t.Def.Type != "service" {
			continue
		}
		if !envMatches(t, name) {
			continue
		}
		h := c.tool(t.Def)
		h.methods["iac"] = true
		h.counts["iac"]++
		if len(h.evidence) < maxEvidenceCollect {
			h.evidence = append(h.evidence, cdx.AIEvidence{
				Method: "iac", Category: "env-name", Locator: loc, Snippet: name,
			})
		}
	}
}

// evalModelArgs extracts model identities from allowlisted flags, handling
// both "--flag value" and "--flag=value".
func (c *collector) evalModelArgs(args []string, loc string) {
	flags := c.cat.Infra.ModelArgFlags
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if flag, value, ok := strings.Cut(arg, "="); ok {
			if flags[flag] && !looksTemplated(value) {
				c.addModel(value, "", "", "", cdx.AIEvidence{
					Method: "iac", Category: "arg", Locator: loc + "#arg:" + flag, Snippet: flag + "=" + value,
				})
			}
			continue
		}
		if flags[arg] && i+1 < len(args) {
			value := args[i+1]
			if !strings.HasPrefix(value, "-") && !looksTemplated(value) {
				c.addModel(value, "", "", "", cdx.AIEvidence{
					Method: "iac", Category: "arg", Locator: loc + "#arg:" + arg, Snippet: arg + " " + value,
				})
			}
		}
	}
}

func (c *collector) addDataFromMount(w *parse.Workload, m parse.WorkloadMount, kind, loc string) {
	d := &dataHit{kind: kind, mountPath: m.MountPath}
	if vol, ok := w.LookupVolume(m.Name); ok {
		d.source = vol.Source
		switch {
		case vol.SourceName != "":
			d.name = vol.Source + ":" + vol.SourceName
		default:
			d.name = vol.Source + ":" + vol.Name
		}
		if vol.Source == "unknown" {
			d.gap = true
			d.gapReason = "volume '" + m.Name + "' backing source unrecognized"
		}
	} else if m.Name != "" {
		d.source = "unknown"
		d.name = "volume:" + m.Name
		d.gap = true
		d.gapReason = "volume '" + m.Name + "' has no matching volumes[] entry"
	} else {
		return // no volume name and no backing source: nothing verifiable
	}
	c.addData(d, cdx.AIEvidence{
		Method: "iac", Category: "mount", Locator: loc,
		Snippet: m.Name + " -> " + m.MountPath,
	})
}

// evalAccelerators surfaces GPU/TPU resource requests and accelerator node
// selectors as a single accelerator infrastructure component.
func (c *collector) evalAccelerators(w *parse.Workload, loc string) {
	keys := c.cat.Infra.GPUResourceKeys
	if len(keys) == 0 {
		return
	}
	for i := range w.Containers {
		for _, rk := range w.Containers[i].ResourceKeys {
			if keys[rk] {
				c.infraHitAccelerator(cdx.AIEvidence{
					Method: "iac", Category: "resource-request", Locator: loc, Snippet: rk,
				})
			}
		}
	}
	for k, v := range w.NodeSelector {
		if keys[k] || strings.Contains(k, "accelerator") {
			c.infraHitAccelerator(cdx.AIEvidence{
				Method: "iac", Category: "node-selector", Locator: loc, Snippet: k + "=" + v,
			})
		}
	}
}

func (c *collector) workloadHasTrainingCRD(w *parse.Workload) bool {
	if w.Raw == nil {
		return false
	}
	for i := range c.cat.Infra.CRDs {
		crd := &c.cat.Infra.CRDs[i]
		if w.Kind == crd.Kind && strings.HasPrefix(w.APIVersion, crd.APIVersionPrefix) && crd.Category == "training" {
			return true
		}
	}
	return false
}

// evalHelmTemplateFallback runs a deliberately narrow regex over a Helm
// template that could not be structurally parsed. Only image lines are
// extracted, and every resulting detection carries a confidence gap.
var helmTemplateImageLine = regexp.MustCompile(`(?m)^[ \t-]*image:[ \t]+["']?([^\s"'#]+)["']?`)

func (c *collector) evalHelmTemplateFallback(p, content string) {
	for _, m := range findSubmatches(content, helmTemplateImageLine) {
		if parse.ImagePlaceholder(m.value) {
			continue
		}
		ref := parse.SplitImageRef(m.value)
		if ref.Name == "" {
			continue
		}
		for i := range c.cat.Infra.Runtimes {
			rt := &c.cat.Infra.Runtimes[i]
			for _, re := range rt.Images {
				if !re.MatchString(ref.Name) {
					continue
				}
				hit := c.infraHitRuntime(rt.Def, ref, cdx.AIEvidence{
					Method: "iac", Category: "helm-template", Locator: p + ":" + itoa(m.line), Snippet: m.value,
				})
				c.infraGap(hit, "helm template: structural parse impossible, regex fallback used")
			}
		}
	}
}

// evalHelmValues walks a chart's values.yaml for image references: both the
// `image: repo:tag` shorthand and the `image: {repository, tag}` block form.
// Templated values are skipped (they cannot be verified from the file).
func (c *collector) evalHelmValues(p, content string) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return
	}
	for _, ref := range helmValuesImageRefs(doc, 0) {
		c.matchImageRef(ref, cdx.AIEvidence{
			Method: "iac", Category: "helm-values", Locator: p, Snippet: ref,
		})
	}
}

// helmValuesImageRefs recursively collects candidate image references from a
// decoded values map (bounded depth — values files are shallow in practice).
func helmValuesImageRefs(node any, depth int) []string {
	if depth > 10 {
		return nil
	}
	var out []string
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	for key, v := range m {
		if key == "image" {
			switch img := v.(type) {
			case string:
				out = append(out, img)
			case map[string]any:
				repo, _ := img["repository"].(string)
				if repo == "" {
					repo, _ = img["name"].(string)
				}
				if repo != "" {
					if tag, _ := img["tag"].(string); tag != "" && !looksTemplated(tag) {
						repo += ":" + tag
					}
					out = append(out, repo)
				}
			}
			continue
		}
		if child, ok := v.(map[string]any); ok {
			out = append(out, helmValuesImageRefs(child, depth+1)...)
		}
	}
	return out
}

// evalKustomization reads the images transformer of a kustomization file:
// entries rewrite `name` to `newName`/`newTag`, which is exactly the image
// the cluster would run.
func (c *collector) evalKustomization(p, content string) {
	var doc struct {
		Images []struct {
			Name    string `yaml:"name"`
			NewName string `yaml:"newName"`
			NewTag  string `yaml:"newTag"`
			Digest  string `yaml:"digest"`
		} `yaml:"images"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return
	}
	for _, img := range doc.Images {
		name := img.NewName
		if name == "" {
			name = img.Name
		}
		if name == "" {
			continue
		}
		ref := name
		if img.NewTag != "" {
			ref += ":" + img.NewTag
		}
		if img.Digest != "" {
			ref += "@" + img.Digest
		}
		c.matchImageRef(ref, cdx.AIEvidence{
			Method: "iac", Category: "kustomize", Locator: p, Snippet: ref,
		})
	}
}

// matchImageRef runs a bare image reference (no container context) through
// the runtime allowlist.
func (c *collector) matchImageRef(raw string, ev cdx.AIEvidence) {
	if parse.ImagePlaceholder(raw) {
		return
	}
	ref := parse.SplitImageRef(raw)
	if ref.Name == "" {
		return
	}
	for i := range c.cat.Infra.Runtimes {
		rt := &c.cat.Infra.Runtimes[i]
		for _, re := range rt.Images {
			if re.MatchString(ref.Name) {
				hit := c.infraHitRuntime(rt.Def, ref, ev)
				if ref.Digest != "" && !ref.DigestValid() {
					c.infraGap(hit, "image digest malformed: "+ref.Digest)
				}
				return
			}
		}
	}
}

// ---- infra/data hit bookkeeping ---------------------------------------------

type infraHit struct {
	def       InfraRuntimeDef
	version   string
	rawTag    string
	image     string
	runtime   string // declared runtime format (CRD), recorded as evidence
	gap       bool
	gapReason string
	evidence  []cdx.AIEvidence
	seenLoc   map[string]bool
}

func (h *infraHit) evidenceAdd(ev cdx.AIEvidence) {
	key := ev.Category + "|" + ev.Locator + "|" + ev.Snippet
	if h.seenLoc[key] {
		return
	}
	h.seenLoc[key] = true
	if len(h.evidence) < maxEvidenceCollect {
		h.evidence = append(h.evidence, ev)
	}
}

type dataHit struct {
	name      string
	kind      string
	source    string
	mountPath string
	gap       bool
	gapReason string
	evidence  []cdx.AIEvidence
}

func (c *collector) infra(def InfraRuntimeDef) *infraHit {
	h := c.infraHits[def.ID]
	if h == nil {
		h = &infraHit{def: def, seenLoc: map[string]bool{}}
		c.infraHits[def.ID] = h
	}
	return h
}

func (c *collector) infraHitRuntime(def InfraRuntimeDef, ref parse.ImageRef, ev cdx.AIEvidence) *infraHit {
	h := c.infra(def)
	if h.image == "" {
		h.image = ref.Raw
	}
	if h.rawTag == "" {
		h.rawTag = ref.Tag
	}
	if h.version == "" {
		if semverShapedTag.MatchString(ref.Tag) {
			h.version = strings.TrimPrefix(ref.Tag, "v")
		} else if ref.Tag != "" {
			c.infraGap(h, "version unverified: image tag '"+ref.Tag+"' is not semver-shaped")
		} else if ref.Digest == "" {
			c.infraGap(h, "version unverified: image reference has no tag")
		}
	}
	h.evidenceAdd(ev)
	return h
}

func (c *collector) infraHitSignal(sig WorkloadEnvSignal, ev cdx.AIEvidence) {
	h := c.infra(InfraRuntimeDef{ID: sig.Framework, Name: sig.Name, Category: sig.Category})
	h.evidenceAdd(ev)
}

func (c *collector) infraHitCRD(crd CRDDef, ev cdx.AIEvidence) *infraHit {
	h := c.infra(InfraRuntimeDef{ID: crd.ID, Name: crd.Name, Category: crd.Category, Homepage: crd.Homepage})
	h.evidenceAdd(ev)
	return h
}

func (c *collector) infraHitAccelerator(ev cdx.AIEvidence) {
	h := c.infra(InfraRuntimeDef{ID: "accelerator", Name: "GPU / accelerator resources", Category: "accelerator"})
	h.evidenceAdd(ev)
}

// infraGap records a confidence gap. A nil hit means the gap has no
// component to attach to (e.g. a secret-referenced model env on a container
// with no matched runtime) — dropped rather than guessed.
func (c *collector) infraGap(h *infraHit, reason string) {
	if h == nil {
		return
	}
	if !h.gap {
		h.gap = true
		h.gapReason = reason
		return
	}
	if !strings.Contains(h.gapReason, reason) {
		h.gapReason += "; " + reason
	}
}

func (c *collector) addData(d *dataHit, ev cdx.AIEvidence) {
	key := d.kind + "|" + d.source + "|" + d.name + "|" + d.mountPath
	if existing, ok := c.dataHits[key]; ok {
		if len(existing.evidence) < maxEvidenceCollect {
			existing.evidence = append(existing.evidence, ev)
		}
		return
	}
	d.evidence = append(d.evidence, ev)
	c.dataHits[key] = d
}

// ---- shared validation helpers ----------------------------------------------

// fieldPresentNonString reports whether a dot-path resolves to a value that
// exists but is not a string (so the caller can flag a confidence gap
// instead of silently skipping a malformed declared field).
func fieldPresentNonString(m map[string]any, dotPath string) bool {
	parts := strings.Split(dotPath, ".")
	var cur any = m
	for _, part := range parts {
		node, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur, ok = node[part]
		if !ok {
			return false
		}
	}
	_, isString := cur.(string)
	return !isString
}

// looksTemplated reports whether a value still carries template or shell
// interpolation syntax and therefore cannot be trusted as a literal.
func looksTemplated(v string) bool {
	return strings.Contains(v, "{{") || strings.Contains(v, "}}") || strings.Contains(v, "${") || strings.HasPrefix(strings.TrimSpace(v), "$")
}

// mountPrefixMatch does a path-boundary prefix match: /models matches
// /models and /models/llama, but never /models-shared.
func mountPrefixMatch(prefixes []string, mountPath string) bool {
	mp := path.Clean(mountPath)
	if mp == "" || !strings.HasPrefix(mp, "/") {
		return false
	}
	for _, prefix := range prefixes {
		if mp == prefix || strings.HasPrefix(mp, prefix+"/") {
			return true
		}
	}
	return false
}
