//go:build !unix

package agent

func selfUsage() (cpuSec float64, rssBytes uint64) { return 0, 0 }
