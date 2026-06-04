package display

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Progress renders one transparent activity line on stderr. A progress activity
// has a static title, a numeric done/total goal, and a stage title that can
// change while work proceeds inside the current stage.
type Progress struct {
	enabled     bool
	interactive bool
	term        *Terminal

	mu       sync.Mutex
	title    string
	stage    string
	done     int
	total    int
	finished bool
	tick     int

	stop  chan struct{}
	donec chan struct{}

	writeMu sync.Mutex
}

// Progress creates and starts a progress activity. When progress is disabled,
// the returned object is a no-op and is safe to use unconditionally.
func (c *Context) Progress(title string, total int) *Progress {
	p := &Progress{
		enabled:     c != nil && !c.Silent && !c.NoProgress,
		interactive: c != nil && c.Term != nil && c.Term.StderrTTY,
		title:       strings.TrimSpace(title),
		total:       total,
		stop:        make(chan struct{}),
		donec:       make(chan struct{}),
	}
	if c != nil {
		p.term = c.Term
	}
	if !p.enabled {
		close(p.donec)
		return p
	}
	if p.title == "" {
		p.title = "Working"
	}
	if p.interactive {
		go p.animate()
		p.render(false)
		return p
	}
	return p
}

// SetStage changes the current stage title without changing numeric progress.
func (p *Progress) SetStage(stage string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.stage = strings.TrimSpace(stage)
	p.mu.Unlock()
	if !p.interactive {
		p.render(false)
	}
}

// Interactive reports whether progress is rendering as a live TTY line.
func (p *Progress) Interactive() bool {
	return p != nil && p.enabled && p.interactive
}

// Writer returns a writer that can be used for ordinary log output while this
// progress activity is active. On interactive terminals it clears the live
// progress row before writing and redraws it afterwards, so log lines do not
// leave behind duplicate progress bars.
func (p *Progress) Writer(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	if p == nil || !p.enabled || !p.interactive {
		return w
	}
	return progressWriter{progress: p, writer: w}
}

// Update sets the numeric progress and, when non-empty, the current stage.
func (p *Progress) Update(done int, stage string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.done = done
	if p.total > 0 && p.done > p.total {
		p.done = p.total
	}
	if p.done < 0 {
		p.done = 0
	}
	if strings.TrimSpace(stage) != "" {
		p.stage = strings.TrimSpace(stage)
	}
	p.mu.Unlock()
	if !p.interactive {
		p.render(false)
	}
}

// Advance moves progress forward by one unit and updates the stage title.
func (p *Progress) Advance(stage string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	p.done++
	if p.total > 0 && p.done > p.total {
		p.done = p.total
	}
	if strings.TrimSpace(stage) != "" {
		p.stage = strings.TrimSpace(stage)
	}
	p.mu.Unlock()
	if !p.interactive {
		p.render(false)
	}
}

// Complete finalizes the activity with a success line.
func (p *Progress) Complete(stage string) {
	p.finish(CheckMark, stage)
}

// Fail finalizes the activity with a failure line.
func (p *Progress) Fail(stage string) {
	p.finish(CrossMark, stage)
}

func (p *Progress) finish(mark func(*Terminal) string, stage string) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	if p.total > 0 {
		p.done = p.total
	}
	if strings.TrimSpace(stage) != "" {
		p.stage = strings.TrimSpace(stage)
	}
	p.mu.Unlock()
	if p.interactive {
		close(p.stop)
		<-p.donec
	}
	p.renderWithMark(mark)
}

func (p *Progress) animate() {
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	defer close(p.donec)
	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			p.tick++
			done := p.finished
			p.mu.Unlock()
			if done {
				return
			}
			p.render(false)
		case <-p.stop:
			return
		}
	}
}

func (p *Progress) render(final bool) {
	p.mu.Lock()
	line := p.line(spinnerFrame(p.tick))
	p.mu.Unlock()
	p.write(line, final)
}

func (p *Progress) renderWithMark(mark func(*Terminal) string) {
	p.mu.Lock()
	line := p.line(mark(p.term))
	p.mu.Unlock()
	p.write(line, true)
}

func (p *Progress) line(prefix string) string {
	parts := []string{prefix, p.title}
	if p.total > 0 {
		pct := 0
		if p.done > 0 {
			pct = p.done * 100 / p.total
		}
		parts = append(parts, fmt.Sprintf("%s %d/%d (%d%%)", Bar(p.term, p.done, p.total, 18), p.done, p.total, pct))
	}
	if p.stage != "" {
		parts = append(parts, p.stage)
	}
	return strings.Join(parts, "  ")
}

func (p *Progress) write(line string, final bool) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.interactive {
		fmt.Fprint(os.Stderr, "\r\033[2K"+line)
		if final {
			fmt.Fprintln(os.Stderr)
		}
		return
	}
	fmt.Fprintln(os.Stderr, line)
}

type progressWriter struct {
	progress *Progress
	writer   io.Writer
}

func (w progressWriter) Write(b []byte) (int, error) {
	p := w.progress
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	fmt.Fprint(w.writer, "\r\033[2K")
	n, err := w.writer.Write(b)
	if err != nil {
		return n, err
	}
	if !p.isFinished() {
		if len(b) == 0 || b[len(b)-1] != '\n' {
			fmt.Fprintln(w.writer)
		}
		fmt.Fprint(w.writer, "\r\033[2K"+p.currentLine())
	}
	return n, nil
}

func (p *Progress) isFinished() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.finished
}

func (p *Progress) currentLine() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.line(spinnerFrame(p.tick))
}

func spinnerFrame(i int) string {
	frames := [...]string{"-", "\\", "|", "/"}
	return frames[i%len(frames)]
}
