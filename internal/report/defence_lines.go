package report

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/defences"
)

// renderDefenceLines is the no-fix block: which of the situations holds, and the
// command that moves it forward.
//
// Optional tails (the mode a rule starts in, "Pro unlocks the rules") are added
// only when they fit the line. A tail is a courtesy; clipping a name is not.
func renderDefenceLines(p Package, o Options, s *Style, indent string) string {
	if o.Hide["defences"] || p.Fix.State != FixNone || p.Defence == nil {
		return ""
	}
	d := p.Defence
	id := p.DefenceID
	if id == "" {
		id = d.ID
	}
	mark := s.Defence(s.G.Defence)
	var b strings.Builder

	emit := func(main string, tails ...string) {
		out := indent + main
		for _, t := range tails {
			if t != "" && vis(out)+vis(t) <= s.Width {
				out += t
			}
		}
		b.WriteString(out + "\n")
	}
	// say prints a sentence after the marker, wrapped to the line.
	say := func(paint func(string) string, text string) {
		room := s.Width - len(indent) - 2
		for i, l := range wrapText(text, room) {
			if i == 0 {
				emit(mark + " " + paint(l))
			} else {
				emit("  " + paint(l))
			}
		}
	}
	cmd := func(text string) { emit(s.Cmd(s.G.Arrow + " " + text)) }

	switch d.State {
	case defences.StateAvailable:
		m, tail := laneText(d.Block, s, true, d.Detect.Count > 0)
		emit(mark+" "+s.Defence("block")+"   "+m, tail)
		m, tail = laneText(d.Detect, s, false, d.Block.Count > 0)
		emit(mark+" "+s.Defence("detect")+"  "+m, tail)
		cmd("vulnetix defend " + id)
	case defences.StateGated:
		m, tail := gatedText(d, s)
		emit(mark+" "+m, tail)
		if o.Verbosity >= 1 {
			emit("  " + s.Dim(kindsText(d)))
		}
	case defences.StateNone:
		emit(mark + " " + s.Dim("nothing published for this yet"))
		cmd("vulnetix vdb workarounds " + id)
	case defences.StateNotIndexed:
		say(s.Dim, fmt.Sprintf("not indexed: %s is not an advisory identifier the database can look up", d.ID))
	case defences.StateNotChecked:
		why := "offline"
		if d.Reason != "" {
			why = d.Reason
		}
		say(s.Dim, "not checked ("+why+")")
	case defences.StateFailed:
		why := "try again"
		if d.Reason != "" {
			why = d.Reason
		}
		say(s.Warn, "lookup failed ("+why+")")
	case defences.StateUnavailable:
		if o.Show["defences"] {
			say(s.Dim, "defence lookup is not available in this version yet")
		}
	}
	return b.String()
}

// laneText renders one lane of an available summary as its body and an optional
// tail. A lane being empty while the other has rules is worth saying; both being
// empty is a different state, handled by the caller.
func laneText(l defences.LaneSummary, s *Style, block, otherHas bool) (main, tail string) {
	if l.Count == 0 {
		if otherHas {
			return s.Dim("nothing published for this yet"), ""
		}
		return s.Dim("none"), ""
	}
	var names []string
	for _, k := range l.Kinds() {
		names = append(names, defences.Name(k))
	}
	main = strings.Join(names, " "+s.G.Sep+" ")
	if block {
		if mode := safeMode(l); mode != "" {
			tail = "     " + s.Dim("start in "+mode)
		}
	}
	return main, tail
}

func gatedText(d *defences.Summary, s *Style) (main, tail string) {
	var parts []string
	if n := d.Block.Count; n > 0 {
		parts = append(parts, fmt.Sprintf("%d block %s", n, pluralWord(n, "rule", "rules")))
	}
	if n := d.Detect.Count; n > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", n, pluralWord(n, "detection", "detections")))
	}
	return strings.Join(parts, " and ") + " exist", s.Dim(" " + s.G.Sep + " Pro unlocks the rules")
}
