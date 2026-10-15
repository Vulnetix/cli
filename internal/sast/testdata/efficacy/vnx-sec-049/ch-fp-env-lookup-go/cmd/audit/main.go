package main

import (
	"fmt"
	"os"
)

func main() {
	key := os.Getenv("ANTHROPIC_ADMIN_KEY")
	if key == "" || len(key) < len("sk-ant-admin01-") {
		fmt.Println("set ANTHROPIC_ADMIN_KEY")
		os.Exit(1)
	}
}
