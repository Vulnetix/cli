package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	n, _ := strconv.Atoi(os.Args[1])
	n = max(1, n)
	fmt.Println(100/n, "per file", "out/"+strconv.Itoa(n))
}
