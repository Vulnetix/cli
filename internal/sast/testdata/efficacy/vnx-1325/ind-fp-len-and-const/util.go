package util

func copyAll(items []string) []string {
	out := make([]string, 0, len(items))
	scratch := make([]byte, 4096)
	_ = scratch
	for _, it := range items {
		out = append(out, it)
	}
	return out
}
