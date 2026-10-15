package store

import "github.com/google/uuid"

func NewRecordID() string {
	id := uuid.Must(uuid.NewUUID()).String()
	return id
}

func NewSessionID() string {
	return uuid.New().String()
}
