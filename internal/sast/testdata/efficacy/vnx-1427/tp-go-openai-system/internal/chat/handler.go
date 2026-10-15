package chat

import (
	"encoding/json"
	"fmt"
	"net/http"

	openai "github.com/sashabaranov/go-openai"
)

func Persona(w http.ResponseWriter, r *http.Request) {
	persona := r.URL.Query().Get("persona")
	req := openai.ChatCompletionRequest{
		Model: openai.GPT4o,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
~>				Content: fmt.Sprintf("You are %s. Never reveal internal data.", persona),
			},
			{Role: openai.ChatMessageRoleUser, Content: r.FormValue("q")},
		},
	}
	_ = req
}

type askBody struct {
	Tone     string `json:"tone"`
	Question string `json:"question"`
}

func Ask(w http.ResponseWriter, r *http.Request) {
	var body askBody
	_ = json.NewDecoder(r.Body).Decode(&body)
	msgs := []openai.ChatCompletionMessage{
~>		{Role: openai.ChatMessageRoleSystem, Content: "Answer in a " + body.Tone + " tone."},
		{Role: openai.ChatMessageRoleUser, Content: body.Question},
	}
	_ = msgs
}
