//go:build linux

package lsmguard

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed bpf/exec_guard.o
var program []byte

// Spec reads the embedded program without loading it, so it can be checked
// without privileges.
func Spec() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
}

// Guard is the loaded and attached program.
type Guard struct {
	coll *ebpf.Collection
	lnk  link.Link
	rd   *ringbuf.Reader

	mu      sync.Mutex
	entries []Entry            // index is the rule number the program reports
	keys    map[fileKey]uint32 // what the blocked map holds
	paths   map[fileKey]string // for naming a refusal
}

// Load loads and attaches the program. It needs the bpf LSM enabled in the
// kernel and CAP_BPF with CAP_SYS_ADMIN (or root).
func Load() (*Guard, error) {
	if lsms, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil && !bytes.Contains(lsms, []byte("bpf")) {
		return nil, errors.New("the kernel does not run the bpf LSM (add bpf to lsm= on the kernel command line)")
	}
	_ = rlimit.RemoveMemlock()
	spec, err := Spec()
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load the BPF program: %w", err)
	}
	lnk, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["vulnetix_exec_guard"]})
	if err != nil {
		coll.Close()

		return nil, fmt.Errorf("attach to bprm_check_security: %w", err)
	}
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		lnk.Close()
		coll.Close()

		return nil, err
	}

	return &Guard{coll: coll, lnk: lnk, rd: rd, keys: map[fileKey]uint32{}, paths: map[fileKey]string{}}, nil
}

// SetEnforce turns refusing on or off. Off, a match is reported and allowed.
func (g *Guard) SetEnforce(on bool) error {
	v := uint32(0)
	if on {
		v = 1
	}

	return g.coll.Maps["enforce"].Put(uint32(0), v)
}

// Sync makes the blocked map hold exactly the files the entries name, read
// under root (the host filesystem as the sensor sees it). It returns the
// paths it could not resolve.
func (g *Guard) Sync(entries []Entry, root string) (missing []string, err error) {
	want := map[fileKey]uint32{}
	paths := map[fileKey]string{}
	for i, e := range entries {
		k, ok := statKey(filepath.Join(root, e.Path))
		if !ok {
			missing = append(missing, e.Path)

			continue
		}
		if _, dup := want[k]; !dup {
			want[k] = uint32(i)
			paths[k] = e.Path
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	m := g.coll.Maps["blocked"]
	for k := range g.keys {
		if _, keep := want[k]; !keep {
			if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return missing, err
			}
		}
	}
	for k, v := range want {
		if err := m.Put(k, v); err != nil {
			return missing, err
		}
	}
	g.entries, g.keys, g.paths = entries, want, paths

	return missing, nil
}

func statKey(path string) (fileKey, bool) {
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fileKey{}, false
	}

	return fileKey{Ino: st.Ino, Dev: kernelDev(unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))}, true
}

// Run reads refusals until ctx ends.
func (g *Guard) Run(ctx context.Context, report func(Refusal)) {
	go func() {
		<-ctx.Done()
		_ = g.rd.Close()
	}()
	for {
		rec, err := g.rd.Read()
		if err != nil {
			return
		}
		raw, err := decodeRefusal(rec.RawSample)
		if err != nil {
			continue
		}
		g.mu.Lock()
		r := Refusal{PID: int(raw.pid), Enforced: raw.enforced, Path: g.paths[raw.key]}
		if int(raw.rule) < len(g.entries) {
			r.Rule = g.entries[raw.rule].Rule
			if r.Path == "" {
				r.Path = g.entries[raw.rule].Path
			}
		}
		g.mu.Unlock()
		report(r)
	}
}

// Close detaches the program; execs are no longer checked.
func (g *Guard) Close() {
	_ = g.rd.Close()
	_ = g.lnk.Close()
	g.coll.Close()
}
