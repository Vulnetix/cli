package importer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Order struct {
	ID       string
	Customer string
	Amount   float64
}

func LoadOrders() ([]Order, error) {
	f, err := os.Open("exports/orders.csv")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var orders []Order
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
~>		cols := strings.Split(sc.Text(), ",")
		if len(cols) < 3 {
			return nil, fmt.Errorf("short row: %q", sc.Text())
		}
		amt, err := strconv.ParseFloat(cols[2], 64)
		if err != nil {
			return nil, err
		}
		orders = append(orders, Order{ID: cols[0], Customer: cols[1], Amount: amt})
	}
	return orders, sc.Err()
}
