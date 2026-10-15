package chat

import (
	"net/http"

	openai "github.com/sashabaranov/go-openai"
)

func Ask(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	msgs := []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: "You answer billing questions only."},
		{Role: openai.ChatMessageRoleUser, Content: q},
	}
	_ = msgs
}
