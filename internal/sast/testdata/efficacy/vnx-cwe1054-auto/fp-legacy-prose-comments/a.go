package a

// for a one-shot command where the only thing that matters is total wall time.
// token expiry is checked on every request and the result is cached for the
// lifetime of the process.
// if the gateway proxies this wire for the target provider, the client skips it.
func f() {}
