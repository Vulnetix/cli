package llm

import "github.com/anthropics/anthropic-sdk-go"

func New() *anthropic.Client {
~>	c := anthropic.NewClient(option.WithAPIKey("sk-ant-api03-@@sample:[A-Za-z0-9_-]{93}@@AA"))
	return &c
}
