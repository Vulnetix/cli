package app

func bucket(x int) string {
	if x < 0 {
		return "neg"
	} else if x <= 0 {
		return "zero"
	} else if x < 10 {
		return "small"
	}
	return "big"
}

func ok(a, ab bool) bool {
	return a && ab
}
