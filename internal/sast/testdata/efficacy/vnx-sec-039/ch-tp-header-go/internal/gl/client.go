package gl

func newReq() {
~>	req.Header.Set("PRIVATE-TOKEN", "@@sample:glpat-[A-Za-z0-9_-]{20}@@")
}
