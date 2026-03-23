package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines all keybindings for the TUI.
type KeyMap struct {
	Quit       key.Binding
	Up         key.Binding
	Down       key.Binding
	Enter      key.Binding
	Tab        key.Binding
	TabScores  key.Binding
	TabExploit key.Binding
	TabTime    key.Binding
	TabFixes   key.Binding
	TabRemed   key.Binding
	Output     key.Binding
	Help       key.Binding
	Escape     key.Binding
	PageUp     key.Binding
	PageDown   key.Binding
}

var keys = KeyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Up: key.NewBinding(
		key.WithKeys("k", "up"),
		key.WithHelp("\u2191/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("j", "down"),
		key.WithHelp("\u2193/j", "down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next tab"),
	),
	TabScores: key.NewBinding(
		key.WithKeys("1"),
		key.WithHelp("1", "scores"),
	),
	TabExploit: key.NewBinding(
		key.WithKeys("2"),
		key.WithHelp("2", "exploits"),
	),
	TabTime: key.NewBinding(
		key.WithKeys("3"),
		key.WithHelp("3", "timeline"),
	),
	TabFixes: key.NewBinding(
		key.WithKeys("4"),
		key.WithHelp("4", "fixes"),
	),
	TabRemed: key.NewBinding(
		key.WithKeys("5"),
		key.WithHelp("5", "remediation"),
	),
	Output: key.NewBinding(
		key.WithKeys("o"),
		key.WithHelp("o", "output"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	Escape: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back"),
	),
	PageUp: key.NewBinding(
		key.WithKeys("pgup", "ctrl+u"),
		key.WithHelp("pgup", "page up"),
	),
	PageDown: key.NewBinding(
		key.WithKeys("pgdown", "ctrl+d"),
		key.WithHelp("pgdn", "page down"),
	),
}

func helpView() string {
	return styleHelp.Render(
		"\u2191\u2193/jk navigate \u2022 1-5 tabs \u2022 o output \u2022 ? help \u2022 q quit",
	)
}
