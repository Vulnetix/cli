package records

import (
	"encoding/csv"
	"os"
	"strings"
)

func Load() ([][]string, error) {
	f, err := os.Open("data/records.csv")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_ = strings.Split("a,b", ",")
	return csv.NewReader(f).ReadAll()
}
