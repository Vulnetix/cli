package cache

import "fmt"

func URL(pw, host string) string { return fmt.Sprintf("redis://:%s@%s:6379/0", pw, host) }
