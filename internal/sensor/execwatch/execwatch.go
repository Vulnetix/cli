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
	"strings"
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
	PID             int
	Binary          string
	Arguments       string
	Cwd             string
	ParentBinary    string
	ParentArguments string
	Pod             string
	Namespace       string
	Time            time.Time
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
				Cwd       string `json:"cwd"`
				Pod       *struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"pod"`
			} `json:"process"`
			Parent *struct {
				Binary    string `json:"binary"`
				Arguments string `json:"arguments"`
			} `json:"parent"`
		} `json:"process_exec"`
		Time time.Time `json:"time"`
	}
	if json.Unmarshal(line, &ev) != nil || ev.ProcessExec == nil || ev.ProcessExec.Process.Binary == "" {
		return Exec{}, false
	}
	p := ev.ProcessExec.Process
	e := Exec{PID: p.PID, Binary: p.Binary, Arguments: p.Arguments, Cwd: p.Cwd, Time: ev.Time}
	if p.Pod != nil {
		e.Pod, e.Namespace = p.Pod.Name, p.Pod.Namespace
	}
	if parent := ev.ProcessExec.Parent; parent != nil {
		e.ParentBinary, e.ParentArguments = parent.Binary, parent.Arguments
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

// Check runs the process rules over one exec: the feeds' Sigma rules against
// the start itself, and the file-hash indicators against the binary. Hashing
// prefers the process's own /proc/<pid>/exe, which is the file that ran even
// if the path was replaced since, and falls back to the path Tetragon
// reported.
func (w *Watcher) Check(e Exec) {
	set := w.Rules()
	if set == nil || !set.HasProcessRules() {
		return
	}
	now := time.Now()
	if !e.Time.IsZero() {
		now = e.Time
	}
	base := map[string]any{"pid": e.PID}
	if e.Pod != "" {
		base["pod"] = e.Namespace + "/" + e.Pod
	}

	commandLine := strings.TrimSpace(e.Binary + " " + e.Arguments)
	for _, hit := range set.MatchProcess(engine.Process{
		Image: e.Binary, CommandLine: commandLine, ParentImage: e.ParentBinary,
		ParentCommandLine: strings.TrimSpace(e.ParentBinary + " " + e.ParentArguments),
		CurrentDirectory:  e.Cwd,
	}) {
		detail := copyMap(base)
		detail["rule"] = hit.Detail
		detail["commandLine"] = clip(commandLine)
		w.report(e, hit.Rule, "countermeasure", detail, now, "sigma")
	}

	if len(set.IOC.Hashes) == 0 {
		return
	}
	sum, path, err := w.hash(e)
	if err != nil {
		return
	}
	if rule, ok := set.IOC.MatchHash(sum); ok {
		detail := copyMap(base)
		detail["sha256"], detail["path"] = sum, path
		w.report(e, rule, "malware", detail, now, sum)
	}
}

// report asks the verdict engine and sends the event. The watcher cannot stop
// a process, so the event always says allowed; when the engine would have
// stopped it, the reason says so instead of claiming a block.
func (w *Watcher) report(e Exec, rule decide.RuleRef, lane string, detail map[string]any, now time.Time, keySalt string) {
	v := w.Verdicts.Decide(decide.Match{Rule: rule, Subject: e.Binary, Reversible: false}, now)
	detail["reason"] = v.Reason
	if v.Action != decide.Allowed {
		detail["reason"] = v.Reason + "; exec watch reports only"
	}
	if w.Report == nil {
		return
	}
	w.Report(uplink.Event{
		EventKey:    newKey(e, keySalt+rule.UUID),
		RuleTable:   rule.Table,
		RuleUUID:    rule.UUID,
		Lane:        lane,
		SubjectKind: "process",
		Subject:     clip(e.Binary),
		Action:      string(decide.Allowed),
		Detail:      detail,
		ObservedAt:  now.UnixMilli(),
	})
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		out[k] = v
	}

	return out
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
