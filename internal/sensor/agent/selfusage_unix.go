//go:build unix

package agent

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// selfUsage is the process's CPU seconds (user + system) and resident memory.
// RSS comes from /proc/self/statm where there is one, and is 0 elsewhere.
func selfUsage() (cpuSec float64, rssBytes uint64) {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		cpuSec = float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
	}
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 1 {
			if pages, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				rssBytes = pages * uint64(os.Getpagesize())
			}
		}
	}

	return cpuSec, rssBytes
}
