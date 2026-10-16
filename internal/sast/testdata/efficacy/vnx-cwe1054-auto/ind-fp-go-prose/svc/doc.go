package svc

// for a one-shot command where the only thing that matters is total wall time.
// token expiry is checked on every request and cached for the process lifetime.
// if the cache is cold the first caller pays the full price.
func Run() {}
