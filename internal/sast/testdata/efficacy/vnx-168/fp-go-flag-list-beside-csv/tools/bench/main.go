package main

import (
	"flag"
	"fmt"
	"strings"
)

// -labels takes project=results.csv pairs; the comma-separated flag value is
// a list of options, not a CSV record, though each entry names a .csv file.
func main() {
	labels := flag.String("labels", "", "project=expectedresults.csv,... (one per project)")
	flag.Parse()
	for _, kv := range strings.Split(*labels, ",") {
		p, path, _ := strings.Cut(kv, "=")
		fmt.Println(p, path)
	}
}
