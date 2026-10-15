package resolve

// Resolve picks the source of a module. The lookup order is:
// if the module is pinned (via the --pin flag)
// for every configured mirror (in declaration order)
// return the first mirror that answers (or the proxy)
// Each step stops at the first hit.
func Resolve(m Module, mirrors []Mirror) Source {
	if m.Pinned {
		return m.Pin
	}
	for _, mi := range mirrors {
		if s, ok := mi.Lookup(m); ok {
			return s
		}
	}
	return Proxy
}
