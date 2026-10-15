package src

import "fmt"

func next(base, pageToken, csrf string) string {
	a := fmt.Sprintf("%s/list?pageToken=%s", base, pageToken)
	b := base + "/list?next_token=" + pageToken
	return a + b + "?show_password_field=" + csrf
}
