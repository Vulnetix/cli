package api

import (
	"errors"
	"net/url"
	"strings"
)

func CleanName(raw string) (string, error) {
	if strings.Contains(raw, "..") {
		return "", errors.New("traversal")
	}
	name, err := url.PathUnescape(raw)
	if err != nil {
		return "", err
	}
	if strings.Contains(name, "..") {
		return "", errors.New("traversal")
	}
	return name, nil
}
