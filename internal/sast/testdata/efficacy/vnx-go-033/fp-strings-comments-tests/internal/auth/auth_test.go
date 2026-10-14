package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParse(t *testing.T) {
	_, err := jwt.Parse(sample, func(*jwt.Token) (any, error) { return testKey, nil })
	if err != nil {
		t.Fatal(err)
	}
}
