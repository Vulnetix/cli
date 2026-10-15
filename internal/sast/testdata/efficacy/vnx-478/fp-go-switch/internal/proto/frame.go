package proto

func name(kind int) string {
	var label string
	switch kind {
	case 1:
		label = "data"
	case 2:
		label = "ping"
	}
	return label
}
