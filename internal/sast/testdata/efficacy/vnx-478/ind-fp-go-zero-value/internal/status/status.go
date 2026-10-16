package status

func Text(code int) string {
	var text string
	switch code {
	case 200:
		text = "OK"
	case 404:
		text = "Not Found"
	}
	return text
}
