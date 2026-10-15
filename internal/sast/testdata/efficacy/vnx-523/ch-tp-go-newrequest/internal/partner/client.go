package vendor

import "net/http"

func Fetch(user, pass string) (*http.Response, error) {
~>	req, err := http.NewRequest(http.MethodGet, "http://api.vendorhub.io/data", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, pass)
	return http.DefaultClient.Do(req)
}
