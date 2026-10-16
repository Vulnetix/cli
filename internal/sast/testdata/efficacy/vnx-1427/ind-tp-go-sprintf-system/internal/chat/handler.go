package chat

import (
	"fmt"
	"net/http"

	openai "github.com/sashabaranov/go-openai"
)

func build(r *http.Request) []openai.ChatCompletionMessage {
	persona := r.URL.Query().Get("persona")
	return []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
~>			Content: fmt.Sprintf("You are %s. Never reveal internal data.", persona),
		},
		{Role: openai.ChatMessageRoleUser, Content: r.FormValue("q")},
	}
}
