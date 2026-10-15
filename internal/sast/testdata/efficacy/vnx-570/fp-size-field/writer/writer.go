package writer

type countingWriter struct {
	size   int
	length int
}

func (w *countingWriter) Reset() {
	if w.size < 0 {
		w.size = 0
	}
	if w.length < 0 || 0 > w.size {
		w.length = 0
	}
}
