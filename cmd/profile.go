package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
)

// startProfiles writes a CPU profile and, when the command returns, a heap
// profile into dir (VULNETIX_PPROF_DIR), for measuring a scan without a
// special build: `go tool pprof dir/cpu.pprof`. An empty dir does nothing. A
// profile that cannot be written is reported and the command runs anyway.
func startProfiles(dir string) (stop func()) {
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "profile: %v\n", err)
		return func() {}
	}
	cpu, err := os.Create(filepath.Join(dir, "cpu.pprof"))
	if err == nil {
		if err = pprof.StartCPUProfile(cpu); err != nil {
			cpu.Close()
			cpu = nil
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "profile: %v\n", err)
	}
	return func() {
		if cpu != nil {
			pprof.StopCPUProfile()
			cpu.Close()
		}
		heap, err := os.Create(filepath.Join(dir, "heap.pprof"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "profile: %v\n", err)
			return
		}
		defer heap.Close()
		runtime.GC()
		// The allocs view of this profile shows what was allocated over the
		// whole run, which is what drives the peak.
		if err := pprof.Lookup("allocs").WriteTo(heap, 0); err != nil {
			fmt.Fprintf(os.Stderr, "profile: %v\n", err)
		}
	}
}
