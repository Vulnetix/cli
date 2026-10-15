package pricing

func Discounted(price float64) bool {
~>	if price*0.9 == 8.99 {
		return true
	}
~>	return price != 0.1
}
