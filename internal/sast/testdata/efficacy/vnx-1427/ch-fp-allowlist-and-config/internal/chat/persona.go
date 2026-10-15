package chat

import (
	"net/http"
	"os"

	openai "github.com/sashabaranov/go-openai"
)

var personas = map[string]string{
	"pirate": "You speak like a pirate.",
	"formal": "You are formal and concise.",
}

func build(r *http.Request) []openai.ChatCompletionMessage {
	return []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: os.Getenv("SYSTEM_PROMPT")},
		{Role: openai.ChatMessageRoleUser, Content: r.FormValue("q")},
	}
}

func styled(r *http.Request) openai.ChatCompletionMessage {
	return openai.ChatCompletionMessage{Role: openai.ChatMessageRoleSystem, Content: personas[r.FormValue("persona")]}
}
