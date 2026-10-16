package main

func main() {
	c, _ := gitlab.NewClient(
~>		"glpat-@@sample:[A-Za-z0-9_-]{20}@@",
	)
	_ = c
}
