package display

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/vulnetix/cli/internal/tui"
)

// Alignment controls column text alignment.
type Alignment int

const (
	AlignLeft Alignment = iota
	AlignRight
)

// Column defines a table column.
type Column struct {
	Header   string
	Width    int                 // 0 = auto-calculate
	MinWidth int                 // minimum width when auto-calculating
	MaxWidth int                 // maximum width when auto-calculating (0 = unlimited)
	Align    Alignment           // left or right alignment
	Color    func(string) string // optional per-cell coloring function
}

// Table renders a responsive table without borders.
// Uses spacing and alignment for visual separation, with bold headers and a thin separator.
func Table(term *Terminal, cols []Column, rows [][]string) string {
	if len(rows) == 0 || len(cols) == 0 {
		return ""
	}

	colWidths := calculateColumnWidths(term, cols, rows)

	var b strings.Builder

	// Header row
	headerLine := renderRow(term, cols, colWidths, headers(cols), true)
	b.WriteString(headerLine)
	b.WriteByte('\n')

	// Separator
	sepWidth := 0
	for _, w := range colWidths {
		sepWidth += w
	}
	sepWidth += (len(colWidths) - 1) * 2 // spacing between columns
	if sepWidth > term.Width {
		sepWidth = term.Width
	}
	b.WriteString(ShortDivider(term, sepWidth))
	b.WriteByte('\n')

	// Data rows
	for _, row := range rows {
		b.WriteString(renderRow(term, cols, colWidths, row, false))
		b.WriteByte('\n')
	}

	return strings.TrimRight(b.String(), "\n")
}

func headers(cols []Column) []string {
	h := make([]string, len(cols))
	for i, c := range cols {
		h[i] = c.Header
	}
	return h
}

func renderRow(term *Terminal, cols []Column, widths []int, cells []string, isHeader bool) string {
	var b strings.Builder
	for i, col := range cols {
		if i >= len(cells) {
			break
		}
		cell := cells[i]
		w := widths[i]

		// Truncate if needed
		if len(cell) > w {
			cell = Truncate(cell, w)
		}

		// Apply styling
		if isHeader && term.HasColor() {
			cell = lipgloss.NewStyle().Bold(true).Foreground(tui.ColorAccent).Render(PadRight(cell, w))
		} else if !isHeader && col.Color != nil {
			cell = col.Color(PadRight(cell, w))
		} else if col.Align == AlignRight {
			cell = PadLeft(cell, w)
		} else {
			cell = PadRight(cell, w)
		}

		b.WriteString(cell)
		if i < len(cols)-1 {
			b.WriteString("  ")
		}
	}
	return b.String()
}

func calculateColumnWidths(term *Terminal, cols []Column, rows [][]string) []int {
	widths := make([]int, len(cols))

	// Start with header widths and explicit widths
	for i, col := range cols {
		if col.Width > 0 {
			widths[i] = col.Width
		} else {
			widths[i] = len(col.Header)
		}
	}

	// Auto-calculate: measure content
	for i, col := range cols {
		if col.Width > 0 {
			continue // fixed width
		}
		for _, row := range rows {
			if i < len(row) && len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
		if col.MinWidth > 0 && widths[i] < col.MinWidth {
			widths[i] = col.MinWidth
		}
		if col.MaxWidth > 0 && widths[i] > col.MaxWidth {
			widths[i] = col.MaxWidth
		}
	}

	// Fit within terminal width
	spacing := (len(cols) - 1) * 2
	totalWidth := spacing
	for _, w := range widths {
		totalWidth += w
	}

	if totalWidth > term.Width {
		// Shrink auto columns proportionally
		excess := totalWidth - term.Width
		autoIndices := []int{}
		for i, col := range cols {
			if col.Width == 0 {
				autoIndices = append(autoIndices, i)
			}
		}
		if len(autoIndices) > 0 {
			shrinkPer := excess / len(autoIndices)
			remainder := excess % len(autoIndices)
			for j, idx := range autoIndices {
				shrink := shrinkPer
				if j < remainder {
					shrink++
				}
				widths[idx] -= shrink
				minW := cols[idx].MinWidth
				if minW == 0 {
					minW = 8
				}
				if widths[idx] < minW {
					widths[idx] = minW
				}
			}
		}
	}

	return widths
}
