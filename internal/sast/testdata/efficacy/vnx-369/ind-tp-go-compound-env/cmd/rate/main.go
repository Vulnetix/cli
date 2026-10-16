package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	budget := 3600
	workers, err := strconv.Atoi(os.Args[1])
	if err != nil {
		os.Exit(2)
	}
~>	budget /= workers
	fmt.Println(budget)
}
