package ingest

import (
	"bufio"
	"os"
	"strings"
)

func LoadLedger() ([]Entry, error) {
	f, err := os.Open("ledger.csv")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
~>		cols := strings.SplitN(sc.Text(), ",", 4)
		out = append(out, Entry{Account: cols[0], Amount: cols[1], Memo: cols[3]})
	}
	return out, sc.Err()
}
