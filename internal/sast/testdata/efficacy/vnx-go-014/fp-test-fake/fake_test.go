package store

// A test double that records calls is not production lock discipline.
func (f *fake) handle() {
	f.mu.Lock()
	f.calls++
}
