package a

func f(items []string) {
	for i := 0; i < len(items); i++ {
		buf := make([]byte, 1024)
		process(buf)
	}
}
