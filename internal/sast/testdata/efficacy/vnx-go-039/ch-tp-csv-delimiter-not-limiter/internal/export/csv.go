package export

import (
	"encoding/csv"
	"io"
)

type Options struct {
	Delimiter rune
}

func Write(w io.Writer, rows [][]string, opts Options) error {
	cw := csv.NewWriter(w)
	if opts.Delimiter != 0 {
		cw.Comma = opts.Delimiter
	}
	defer cw.Flush()
	return cw.WriteAll(rows)
}
