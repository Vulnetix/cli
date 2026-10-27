package cmd

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// applyScanMemoryLimit gives the Go runtime a soft memory limit for a scan, so
// the garbage collector runs harder as the process nears the machine's memory
// instead of the kernel killing it. A SAST run on an 8 GB CI runner was
// OOM-killed with much of its heap already garbage. An explicit GOMEMLIMIT
// always wins.
func applyScanMemoryLimit() {
	_, set := os.LookupEnv("GOMEMLIMIT")
	if limit := scanMemoryLimit(set, cgroupMemoryMax(), memTotal()); limit > 0 {
		debug.SetMemoryLimit(limit)
	}
}

// scanMemoryLimit is 75% of the smaller known ceiling (the cgroup's
// memory.max, then physical memory), or 0 to leave the runtime alone.
func scanMemoryLimit(envSet bool, cgroupMax, total int64) int64 {
	if envSet {
		return 0
	}
	ceiling := total
	if cgroupMax > 0 && (ceiling <= 0 || cgroupMax < ceiling) {
		ceiling = cgroupMax
	}
	if ceiling <= 0 {
		return 0
	}
	return ceiling / 4 * 3
}

// cgroupMemoryMax reads memory.max for this process's cgroup (v2), or 0 when
// there is none, it is "max", or this is not Linux.
func cgroupMemoryMax() int64 {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0
	}
	return cgroupLimit(string(data), "/sys/fs/cgroup")
}

func cgroupLimit(selfCgroup, root string) int64 {
	for line := range strings.SplitSeq(selfCgroup, "\n") {
		rel, ok := strings.CutPrefix(strings.TrimSpace(line), "0::")
		if !ok {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel), "memory.max"))
		if err != nil {
			return 0
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return 0 // "max"
		}
		return n
	}
	return 0
}

// memTotal is physical memory from /proc/meminfo, or 0 off Linux.
func memTotal() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if rest, ok := strings.CutPrefix(s.Text(), "MemTotal:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err != nil {
				return 0
			}
			return kb << 10
		}
	}
	return 0
}
