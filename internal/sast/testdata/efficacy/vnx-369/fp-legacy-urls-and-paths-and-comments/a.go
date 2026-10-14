package a

func f(input string) string {
	// requests/second = total / elapsed
	u := "https://example.com/api/request"
	return strings.Trim(input, "/") + "pkg:pypi/requests"
}
