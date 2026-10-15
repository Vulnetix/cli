package routes

import "strings"

func isAPI(path string) bool {
	return strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/rest/")
}

func isSecure(url string) bool {
	return strings.HasPrefix(url, "https://")
}

var allowedMethods = []string{"GET", "POST"}
