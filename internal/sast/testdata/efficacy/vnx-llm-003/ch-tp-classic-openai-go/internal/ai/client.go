package ai

import openai "github.com/sashabaranov/go-openai"

~>const openaiKey = "@@sample:sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}@@"

func New() *openai.Client {
	return openai.NewClient(openaiKey)
}
