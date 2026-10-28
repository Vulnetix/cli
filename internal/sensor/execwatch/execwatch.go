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
	"github.com/vulnetix/cli/v3/internal/sensor/tetragon"
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
	// PreExec is an exec that has not happened yet (the seccomp guard asks
	// before it runs): /proc/<pid>/exe is still the caller, so the binary is
	// read from its path.
	PreExec bool
	// KernelRefused is an exec the Tetragon policy already refused. The
	// rules are run again to name the rule, and the event says blocked.
	KernelRefused bool
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
	if json.Unmarshal(line, &ev) != nil {
		return Exec{}, false
	}
	if ev.ProcessExec == nil || ev.ProcessExec.Process.Binary == "" {
		return parseRefusal(line)
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

// parseRefusal reads the event Tetragon writes when the policy from
// `vulnetix-sensor tetragon-policy` refuses an exec. The process in it is the
// caller, still running its old image; the program it tried to start is the
// linux_binprm argument.
func parseRefusal(line []byte) (Exec, bool) {
	var ev struct {
		ProcessKprobe *struct {
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
			FunctionName string `json:"function_name"`
			PolicyName   string `json:"policy_name"`
			Action       string `json:"action"`
			Args         []struct {
				Binprm *struct {
					Path string `json:"path"`
				} `json:"linux_binprm_arg"`
			} `json:"args"`
		} `json:"process_kprobe"`
		Time time.Time `json:"time"`
	}
	if json.Unmarshal(line, &ev) != nil || ev.ProcessKprobe == nil {
		return Exec{}, false
	}
	k := ev.ProcessKprobe
	if k.PolicyName != tetragon.PolicyName || k.FunctionName != tetragon.Hook || k.Action != "KPROBE_ACTION_OVERRIDE" ||
		len(k.Args) == 0 || k.Args[0].Binprm == nil || k.Args[0].Binprm.Path == "" {
		return Exec{}, false
	}
	p := k.Process
	e := Exec{
		PID: p.PID, Binary: k.Args[0].Binprm.Path, Cwd: p.Cwd, Time: ev.Time,
		ParentBinary: p.Binary, ParentArguments: p.Arguments, PreExec: true, KernelRefused: true,
	}
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

	yaraSet  *engine.Set
	yaraHits map[string][]engine.Hit
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
func (w *Watcher) Check(e Exec) { w.evaluate(e, false) }

// Gate runs the same rules over an exec that has not happened yet and says
// whether to refuse it. Refusing an exec can be undone (the next one can be
// allowed), so the verdict engine may hold or block it, and the event says
// what was done.
func (w *Watcher) Gate(e Exec) (refuse bool) { return w.evaluate(e, true) }

func (w *Watcher) evaluate(e Exec, gate bool) (refuse bool) {
	set := w.Rules()
	if set == nil || !set.HasProcessRules() {
		return false
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
		refuse = w.report(e, hit.Rule, "countermeasure", detail, now, "sigma", gate) || refuse
	}

	if len(set.IOC.Hashes) == 0 && !set.HasFileRules() {
		return refuse
	}
	sum, path, err := w.hash(e)
	if err != nil {
		return refuse
	}
	if rule, ok := set.IOC.MatchHash(sum); ok {
		detail := copyMap(base)
		detail["sha256"], detail["path"] = sum, path
		refuse = w.report(e, rule, "malware", detail, now, sum, gate) || refuse
	}
	for _, hit := range w.yara(set, path, sum) {
		detail := copyMap(base)
		detail["sha256"], detail["path"], detail["rule"] = sum, path, hit.Detail
		refuse = w.report(e, hit.Rule, "malware", detail, now, "yara"+sum, gate) || refuse
	}

	return refuse
}

// yara runs the YARA rules over a binary, once per content: results are
// cached by hash, and the cache is dropped whenever the rule set changes.
func (w *Watcher) yara(set *engine.Set, path, sum string) []engine.Hit {
	if !set.HasFileRules() {
		return nil
	}
	w.mu.Lock()
	if w.yaraSet != set {
		w.yaraSet, w.yaraHits = set, map[string][]engine.Hit{}
	}
	if hits, ok := w.yaraHits[sum]; ok {
		w.mu.Unlock()

		return hits
	}
	w.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil || info.Size() > engine.MaxYaraFile {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	hits := set.MatchFile(data)
	w.mu.Lock()
	w.yaraHits[sum] = hits
	w.mu.Unlock()

	return hits
}

// report asks the verdict engine, sends the event, and says whether the exec
// is refused. Watching (gate false), the process already runs and cannot be
// stopped, so the event says allowed and, when the engine would have stopped
// it, the reason says so instead of claiming a block.
func (w *Watcher) report(e Exec, rule decide.RuleRef, lane string, detail map[string]any, now time.Time, keySalt string, gate bool) bool {
	v := w.Verdicts.Decide(decide.Match{Rule: rule, Subject: e.Binary, Reversible: gate}, now)
	action := decide.Allowed
	detail["reason"] = v.Reason
	switch {
	case e.KernelRefused:
		action = decide.Blocked
		detail["reason"] = "refused in the kernel by the Tetragon policy " + tetragon.PolicyName
	case gate:
		action = v.Action
	case v.Action != decide.Allowed:
		detail["reason"] = v.Reason + "; exec watch reports only"
	}
	refuse := action != decide.Allowed
	if w.Report == nil {
		return refuse
	}
	w.Report(uplink.Event{
		EventKey:    newKey(e, keySalt+rule.UUID),
		RuleTable:   rule.Table,
		RuleUUID:    rule.UUID,
		Lane:        lane,
		SubjectKind: "process",
		Subject:     clip(e.Binary),
		Action:      string(action),
		Detail:      detail,
		ObservedAt:  now.UnixMilli(),
	})

	return refuse
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
	if e.PreExec {
		candidates = candidates[1:]
	}
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
