package display

// Hyperlink renders a link a terminal can open: an OSC 8 hyperlink around
// text when stdout is a terminal that takes colour, and the bare URL otherwise.
// Piped output and NO_COLOR get the URL itself, which is the useful thing to
// keep in a log or a file.
func (t *Terminal) Hyperlink(url, text string) string {
	if t == nil || !t.IsTTY || !t.HasColor() || text == "" {
		return url
	}
	return "\x1b]8;;" + url + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}
