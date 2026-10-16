package auth

import "github.com/google/uuid"

func NewSessionID() string {
	sessionID := uuid.New().String()
	return sessionID
}

func DocumentID(name string) uuid.UUID {
	docID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(name))
	return docID
}
