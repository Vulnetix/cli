package chat

import (
	"net/http"

	openai "github.com/sashabaranov/go-openai"
)

func (s *Server) Ask(w http.ResponseWriter, r *http.Request) {
	persona := r.URL.Query().Get("persona")
	req := openai.ChatCompletionRequest{
		Model: openai.GPT4o,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
~>				Content: persona,
			},
			{Role: openai.ChatMessageRoleUser, Content: r.FormValue("q")},
		},
	}
	s.reply(w, req)
}
