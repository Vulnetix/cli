package llm

import "net/http"

func newReq(body string) (*http.Request, error) {
	req, err := http.NewRequest("POST", "https://api.groq.com/openai/v1/chat/completions", nil)
	if err != nil {
		return nil, err
	}
~>	req.Header.Set("Authorization", "Bearer gsk_@@sample:[A-Za-z0-9]{52}@@")
	return req, nil
}
