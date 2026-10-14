package a

func f(resp *http.Response) error {
	return json.NewDecoder(resp.Body).Decode(&out)
}
