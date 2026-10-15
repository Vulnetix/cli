package main

import "strings"

func parse(s string) (string, string) {
	k, v, _ := strings.Cut(s, "=")
	return k, v
}

func parseAll(s string) []string {
	return strings.Split(s, "=")
}
