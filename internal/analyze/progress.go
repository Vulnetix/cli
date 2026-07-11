package analyze

// Progress reporting.
//
// `analyze` walks history, parses every source file with tree-sitter, samples complexity
// across commits, and makes a few hundred GitHub calls. On a large repository that is minutes
// of silence, and silence is indistinguishable from a hang — people kill the process and file
// a bug about it.
//
// The interface lives here rather than the collectors importing the display package, so that
// nothing in this package knows or cares whether a terminal is attached. The command wires an
// adapter over display.Progress; a test wires nothing and the calls are no-ops.

// Reporter receives progress updates. A nil Reporter is valid and does nothing, so every
// collector can call it unconditionally.
type Reporter interface {
	// Stage sets what is happening now, without advancing the step count. Used for the long
	// passes, where "Walking history (3,400 commits)" is the difference between a tool that is
	// working and a tool that has hung.
	Stage(msg string)

	// Step advances to a completed step.
	Step(done int, msg string)
}

// The steps, in the order Run actually executes them.
//
// The order matters, and it is the order of execution rather than any tidier grouping: a step
// number that is lower than the one before it makes the bar run backwards, which reads as a
// bug in the tool rather than a bug in the numbering.
const (
	stepGit = iota + 1
	stepFiles
	stepDeps
	stepEnrich
	stepTrust
	stepCoupling
	stepTrend
	stepSymbols
	stepContracts
	stepForge
	stepReport

	TotalSteps = stepReport
)

// reporter wraps a possibly-nil Reporter so collectors never nil-check.
type reporter struct{ r Reporter }

func (p reporter) Stage(msg string) {
	if p.r != nil {
		p.r.Stage(msg)
	}
}

func (p reporter) Step(done int, msg string) {
	if p.r != nil {
		p.r.Step(done, msg)
	}
}

// plural renders a count with its unit, because "1 commits" reads like a bug.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}

	return commas(n) + " " + many
}

// commas groups a number for reading. A progress line saying "walking 148293 commits" makes
// the reader do arithmetic to find out whether that is a lot.
func commas(n int) string {
	if n < 0 {
		return "0"
	}
	s := itoa(n)
	if len(s) <= 3 {
		return s
	}

	out := make([]byte, 0, len(s)+len(s)/3)
	pre := len(s) % 3
	if pre > 0 {
		out = append(out, s[:pre]...)
	}
	for i := pre; i < len(s); i += 3 {
		if len(out) > 0 {
			out = append(out, ',')
		}
		out = append(out, s[i:i+3]...)
	}

	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}

	return string(b[i:])
}
