package users

import (
	"math/rand"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func init() {
	rand.Seed(time.Now().UnixNano())
}

// GenerateTemporaryPassword builds the password mailed to a new user.
func GenerateTemporaryPassword(n int) string {
	out := make([]byte, n)
	for i := range out {
~>		out[i] = charset[rand.Intn(len(charset))]
	}
	return string(out)
}

func (s *Service) resetUser(u *User) {
~>	u.ResetToken = randomString(rand.Int63())
	s.save(u)
}
