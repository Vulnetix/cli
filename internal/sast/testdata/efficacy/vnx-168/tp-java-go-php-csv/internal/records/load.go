package records

import (
	"bufio"
	"os"
	"strings"
)

func Load() ([][]string, error) {
	f, err := os.Open("data/records.csv")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
~>		out = append(out, strings.Split(sc.Text(), ","))
	}
	return out, sc.Err()
}
