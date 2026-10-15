package registry

// Callers must not do this:
//
//	r.mu.Lock()
//	r.mu.Lock()
//
// because sync.Mutex is not reentrant.
func noop() {}
