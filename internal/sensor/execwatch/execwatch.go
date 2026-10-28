// Package execwatch reads process starts from Tetragon and checks each new
// executable against the feeds' file-hash indicators.
//
// Tetragon (Cilium) does the kernel side with eBPF and writes one JSON object
// per event to its export file (--export-filename, by default
// /var/run/cilium/tetragon/tetragon.log). Reading that file instead of its gRPC
// API keeps the sensor free of the gRPC stack, and works the same on a node
// where Tetragon runs as a DaemonSet or a systemd unit.
//
// This is detection only. A match is reported; the process is not stopped,
// because stopping it cannot be undone and the sensor does not yet have a
// kernel hook that refuses the exec before it runs. The sensor reports the
// capability accordingly, and the console says so.
package execwatch

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

// DefaultExport is Tetragon's default export file.
const DefaultExport = "/var/run/cilium/tetragon/tetragon.log"

// Exec is one process start.
type Exec struct {
	PID       int
	Binary    string
	Arguments string
	Pod       string
	Namespace string
	Time      time.Time
}

// ParseLine reads one Tetragon export line. ok is false for any event that is
// not a process_exec.
func ParseLine(line []byte) (Exec, bool) {
	var ev struct {
		ProcessExec *struct {
			Process struct {
				PID       int    `json:"pid"`
				Binary    string `json:"binary"`
				Arguments string `json:"arguments"`
				Pod       *struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"pod"`
			} `json:"process"`
		} `json:"process_exec"`
		Time time.Time `json:"time"`
	}
	if json.Unmarshal(line, &ev) != nil || ev.ProcessExec == nil || ev.ProcessExec.Process.Binary == "" {
		return Exec{}, false
	}
	p := ev.ProcessExec.Process
	e := Exec{PID: p.PID, Binary: p.Binary, Arguments: p.Arguments, Time: ev.Time}
	if p.Pod != nil {
		e.Pod, e.Namespace = p.Pod.Name, p.Pod.Namespace
	}

	return e, true
}

// Watcher checks execs against the current rule set.
type Watcher struct {
	// Root is the filesystem binaries are read from: "/" on the host, or the
	// host root mounted into the sensor's container.
	Root     string
	Rules    func() *engine.Set
	Verdicts *decide.Engine
	Report   func(uplink.Event)

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	size    int64
	modTime time.Time
	sum     string
}

// maxHashBytes skips files too large to be worth hashing on every start.
const maxHashBytes = 256 << 20

// Check hashes the exec's binary and reports a match. It prefers the
// process's own /proc/<pid>/exe, which is the file that ran even if the path
// was replaced since, and falls back to the path Tetragon reported.
func (w *Watcher) Check(e Exec) {
	set := w.Rules()
	if set == nil || len(set.IOC.Hashes) == 0 {
		return
	}
	sum, path, err := w.hash(e)
	if err != nil {
		return
	}
	rule, ok := set.IOC.MatchHash(sum)
	if !ok {
		return
	}
	now := time.Now()
	if !e.Time.IsZero() {
		now = e.Time
	}
	subject := e.Binary
	v := w.Verdicts.Decide(decide.Match{Rule: rule, Subject: subject, Reversible: false}, now)
	detail := map[string]any{"sha256": sum, "path": path, "reason": v.Reason, "pid": e.PID}
	if e.Pod != "" {
		detail["pod"] = e.Namespace + "/" + e.Pod
	}
	if v.Action != decide.Allowed {
		// The verdict engine would stop it; this watcher cannot, and says so
		// rather than reporting a block that did not happen.
		detail["reason"] = v.Reason + "; exec watch reports only"
	}
	if w.Report != nil {
		w.Report(uplink.Event{
			EventKey:    newKey(e, sum),
			RuleTable:   rule.Table,
			RuleUUID:    rule.UUID,
			Lane:        "malware",
			SubjectKind: "process",
			Subject:     clip(subject),
			Action:      string(decide.Allowed),
			Detail:      detail,
			ObservedAt:  now.UnixMilli(),
		})
	}
}

func (w *Watcher) hash(e Exec) (string, string, error) {
	root := w.Root
	if root == "" {
		root = "/"
	}
	candidates := []string{filepath.Join(root, "proc", strconv.Itoa(e.PID), "exe"), filepath.Join(root, e.Binary)}
	var lastErr error
	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil {
			lastErr = err

			continue
		}
		if !info.Mode().IsRegular() || info.Size() > maxHashBytes {
			return "", "", errors.New("not a hashable file")
		}
		// Keyed on the reported path, not /proc/<pid>/exe, which differs per
		// process. A replaced file has a different size or time and is
		// hashed again.
		key := e.Binary
		w.mu.Lock()
		if c, ok := w.cache[key]; ok && c.size == info.Size() && c.modTime.Equal(info.ModTime()) {
			w.mu.Unlock()

			return c.sum, p, nil
		}
		w.mu.Unlock()

		f, err := os.Open(p)
		if err != nil {
			lastErr = err

			continue
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			lastErr = err

			continue
		}
		sum := hex.EncodeToString(h.Sum(nil))
		w.mu.Lock()
		if w.cache == nil {
			w.cache = map[string]cached{}
		}
		w.cache[key] = cached{size: info.Size(), modTime: info.ModTime(), sum: sum}
		w.mu.Unlock()

		return sum, p, nil
	}

	return "", "", lastErr
}

// Follow tails a Tetragon export file from its end, reopening it when it is
// rotated, and calls fn for every exec until ctx ends.
func Follow(ctx context.Context, path string, fn func(Exec)) error {
	var (
		f      *os.File
		reader *bufio.Reader
		ino    uint64
	)
	open := func(seekEnd bool) error {
		nf, err := os.Open(path)
		if err != nil {
			return err
		}
		if seekEnd {
			if _, err := nf.Seek(0, io.SeekEnd); err != nil {
				_ = nf.Close()

				return err
			}
		}
		if f != nil {
			_ = f.Close()
		}
		f, reader, ino = nf, bufio.NewReaderSize(nf, 1<<20), inode(path)

		return nil
	}
	if err := open(true); err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var partial []byte
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			partial = append(partial, line...)
			if line[len(line)-1] == '\n' {
				if e, ok := ParseLine(partial); ok {
					fn(e)
				}
				partial = partial[:0]
			}
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(250 * time.Millisecond):
		}
		// Rotated: a new file under the same name. Read it from the start.
		if now := inode(path); now != 0 && now != ino {
			if err := open(false); err != nil {
				return err
			}
			partial = partial[:0]
		}
	}
}

func newKey(e Exec, sum string) string {
	h := sha256.Sum256([]byte(strconv.Itoa(e.PID) + "|" + e.Time.String() + "|" + sum))

	return hex.EncodeToString(h[:16])
}

func clip(s string) string {
	if r := []rune(s); len(r) > 512 {
		return string(r[:512])
	}

	return s
}
