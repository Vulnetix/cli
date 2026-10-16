package chat

import (
	"net/http"

	openai "github.com/sashabaranov/go-openai"
)

var personas = map[string]string{
	"pirate": "You talk like a pirate.",
	"poet":   "You answer in verse.",
}

func build(r *http.Request) openai.ChatCompletionMessage {
	return openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleSystem,
		Content: personas[r.FormValue("p")],
	}
}
