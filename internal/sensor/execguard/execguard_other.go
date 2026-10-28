//go:build !(linux && (amd64 || arm64))

package execguard

import "errors"

// ChildEnv marks the re-executed sensor; unused off Linux.
const ChildEnv = "__VULNETIX_EXECGUARD_CHILD"

// Exec is one program start the workload asked for.
type Exec struct {
	PID  int
	Path string
	Argv []string
}

// Decider answers an exec.
type Decider func(Exec) error

// MaybeChild does nothing off Linux.
func MaybeChild() {}

// Run is only available on Linux amd64 and arm64.
func Run([]string, Decider) (int, error) {
	return 0, errors.New("the exec guard needs Linux on amd64 or arm64")
}
