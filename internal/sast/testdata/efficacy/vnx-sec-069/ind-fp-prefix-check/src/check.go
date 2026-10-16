package main

import "strings"

func isAge(s string) bool { return strings.HasPrefix(s, "AGE-SECRET-KEY-1") }
