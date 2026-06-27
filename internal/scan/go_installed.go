package scan

func init() {
	gateRegistry["golang"] = gateSpec{
		gated: func(t string) bool { return t == "go.mod" },
		lockPresent: func(dir string) bool {
			return anySiblingExists(dir, []string{"go.sum"})
		},
		// go.mod records exact versions (never ranges), so it is always scannable
		// at exact versions without resolving — the gate is a deliberate no-op. The
		// transitive tree + hashes come from go.sum / `go mod graph` / vendor in the
		// edge builder, not here; a missing go.sum is a non-fatal gap, never an exit.
		fullyPinned: func([]ScopedPackage) bool { return true },
		resolve: func(_, _ string, declared []ScopedPackage, _ bool) ([]ScopedPackage, error) {
			return declared, nil
		},
	}
}
