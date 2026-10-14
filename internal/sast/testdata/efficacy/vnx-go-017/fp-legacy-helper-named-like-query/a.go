package a

func f(year, month int) {
	recordVDBQuery("ids", fmt.Sprintf("%d/%02d", year, month))
}
