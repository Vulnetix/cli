package retry

func Do(f func() error) error { return f() }
