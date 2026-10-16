package ops

// Never do: exec.Command("sh", "-c", fmt.Sprintf("rm %s", p))
func Safe(p string) string {
	msg := `exec.Command("sh", "-c", "x" + p)`
	return msg
}
