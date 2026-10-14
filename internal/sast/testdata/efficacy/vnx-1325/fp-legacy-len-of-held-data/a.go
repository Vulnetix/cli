package a

func f(items []string) []string {
	out := make([]string, 0, len(items))
	rows := make([][]string, len(items))
	buf := make([]byte, 4096)
	return append(out, rows...)
}
