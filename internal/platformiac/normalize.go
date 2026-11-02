package platformiac

// Singleton kinds have a repository form older than the config form: the
// fields at the top level with no metadata (.vulnetix/license-policy.yaml as
// vulnetix license policy init writes it), or metadata without a name
// (.vulnetix/ai-firewall.yaml). Both forms validate. Normalize gives the
// config form the engine reads; Flatten gives the repository form the CLI's
// own parsers read.

// envelope are the keys that are not part of a document's spec.
var envelope = map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "spec": true, "$schema": true}

// Normalize returns the config form: metadata.name defaults to "default",
// and top-level fields move under spec.
func Normalize(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := map[string]any{}
	spec, _ := m["spec"].(map[string]any)
	flat := map[string]any{}
	for k, val := range m {
		if envelope[k] {
			if k != "spec" && k != "$schema" {
				out[k] = val
			}
			continue
		}
		flat[k] = val
	}
	if spec == nil && len(flat) > 0 {
		spec = flat
	}
	if spec == nil {
		spec = map[string]any{}
	}
	out["spec"] = spec
	md, _ := out["metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
	} else {
		cp := map[string]any{}
		for k, val := range md {
			cp[k] = val
		}
		md = cp
	}
	if name, _ := md["name"].(string); name == "" {
		md["name"] = "default"
	}
	out["metadata"] = md
	return out
}

// Flatten returns the repository form: apiVersion and kind, with spec's
// fields at the top level. A document already flat passes through.
func Flatten(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	spec, ok := m["spec"].(map[string]any)
	if !ok {
		return m
	}
	out := map[string]any{"apiVersion": m["apiVersion"], "kind": m["kind"]}
	for k, val := range spec {
		out[k] = val
	}
	return out
}
