package display

import (
	"fmt"
	"strings"
)

// NumberedList renders a numbered list (1-indexed).
func NumberedList(term *Terminal, items []string) string {
	if len(items) == 0 {
		return ""
	}
	// Calculate digit width for alignment
	digitWidth := len(fmt.Sprintf("%d", len(items)))
	format := fmt.Sprintf("  %%%dd. %%s", digitWidth)

	var b strings.Builder
	for i, item := range items {
		line := fmt.Sprintf(format, i+1, item)
		b.WriteString(line)
		if i < len(items)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// BulletList renders a bullet-point list.
func BulletList(term *Terminal, items []string) string {
	if len(items) == 0 {
		return ""
	}
	bullet := "•"
	if !term.HasColor() {
		bullet = "-"
	}
	var b strings.Builder
	for i, item := range items {
		b.WriteString("  " + bullet + " " + item)
		if i < len(items)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// Paginator renders pagination info when there are more results.
func Paginator(term *Terminal, total, limit, offset int, hasMore bool) string {
	if total == 0 {
		return ""
	}
	showing := offset + limit
	if showing > total {
		showing = total
	}

	info := fmt.Sprintf("Showing %s-%s of %s",
		FormatNumber(offset+1), FormatNumber(showing), FormatNumber(total))

	if hasMore {
		hint := fmt.Sprintf("  Use --offset %d for next page", offset+limit)
		return Muted(term, info+hint)
	}
	return Muted(term, info)
}

// CountHeader renders a "Found N items" header with an optional qualifier.
func CountHeader(term *Terminal, count int, noun string) string {
	return Bold(term, fmt.Sprintf("Found %s %s", FormatNumber(count), noun))
}
