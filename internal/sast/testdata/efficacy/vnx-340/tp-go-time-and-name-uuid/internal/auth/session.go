package auth

import "github.com/google/uuid"

func Issue() string {
~>	token := uuid.Must(uuid.NewUUID()).String()
	return token
}

func NewSessionID(user string) string {
~>	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(user)).String()
}
