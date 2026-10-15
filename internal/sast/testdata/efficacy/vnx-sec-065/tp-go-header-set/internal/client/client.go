package client

import "net/http"

func newRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
~>	req.Header.Set("Authorization", "Basic @@sample:c[3]Zj[L]WR[l]cG[x]ve[T]pU[c]Th[2]TD[J]tW[n]A5[V]3g[=]@@")
	return req, nil
}
