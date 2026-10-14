package scan

import (
	"errors"
	"fmt"
)

func init() {
	gateRegistry["swift"] = gateSpec{
		gated:       func(t string) bool { return t == "Package.swift" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"Package.resolved"}) },
		fullyPinned: allVersionsPinned, // `exact:` pins; `from:` is a minimum and is not
		resolve: func(_, relPath string, _ []ScopedPackage, _ bool) ([]ScopedPackage, error) {
			return nil, errors.New(swiftResolveHint(relPath))
		},
	}
}

func swiftResolveHint(relPath string) string {
	return fmt.Sprintf("%s has no Package.resolved and its dependencies are version ranges: resolve them (swift package resolve) and commit Package.resolved, then re-run the scan", relPath)
}
