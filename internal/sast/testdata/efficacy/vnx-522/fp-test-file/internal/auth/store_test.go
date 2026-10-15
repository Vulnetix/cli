package auth

import "os"

func writeFixture(dir, token string) {
	os.WriteFile(dir+"/token", []byte(token), 0644)
}
