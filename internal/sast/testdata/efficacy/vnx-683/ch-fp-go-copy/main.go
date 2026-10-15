package main

func main() {
	src := []byte("abc")
	dst := make([]byte, 3)
	copy(dst, src)
}
