package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	v, _ := strconv.Atoi(os.Args[1])
~>	level := int8(v)
	fmt.Println(level)
}
