package strutil

func LastSpace(s string) int {
~>	for i := uint(len(s)) - 1; i >= 0; i-- {
		if s[i] == ' ' {
			return int(i)
		}
	}
	return -1
}
