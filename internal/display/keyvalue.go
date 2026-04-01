package display

import (
	"strings"
)

// KVPair represents a key-value pair for display.
type KVPair struct {
	Key        string
	Value      string
	ValueStyle func(string) string // optional styling for the value
}

// KeyValue renders aligned key-value pairs.
// An empty Key creates a blank separator line between groups.
func KeyValue(term *Terminal, pairs []KVPair) string {
	// Find max key length for alignment
	maxKey := 0
	for _, p := range pairs {
		if p.Key != "" && len(p.Key) > maxKey {
			maxKey = len(p.Key)
		}
	}

	// Limit key column to reasonable width
	maxKeyCol := term.Width / 3
	if maxKeyCol < 20 {
		maxKeyCol = 20
	}
	if maxKey > maxKeyCol {
		maxKey = maxKeyCol
	}

	var b strings.Builder
	for _, p := range pairs {
		if p.Key == "" {
			b.WriteByte('\n')
			continue
		}
		key := PadRight(p.Key+":", maxKey+1)
		key = Label(term, key)

		value := p.Value
		if p.ValueStyle != nil {
			value = p.ValueStyle(value)
		}

		b.WriteString("  " + key + " " + value + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// KeyValueCompact renders key-value pairs with minimal spacing.
func KeyValueCompact(term *Terminal, pairs []KVPair) string {
	var b strings.Builder
	for _, p := range pairs {
		if p.Key == "" {
			b.WriteByte('\n')
			continue
		}
		key := Label(term, p.Key+":")
		value := p.Value
		if p.ValueStyle != nil {
			value = p.ValueStyle(value)
		}
		b.WriteString("  " + key + " " + value + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
