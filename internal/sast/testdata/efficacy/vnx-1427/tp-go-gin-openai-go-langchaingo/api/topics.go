package api

import (
	"github.com/gin-gonic/gin"
	"github.com/openai/openai-go"
	"github.com/tmc/langchaingo/llms"
)

func Topic(c *gin.Context) {
	topic := c.Query("topic")
	params := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
~>			openai.SystemMessage("You are an expert on " + topic),
			openai.UserMessage(c.Query("q")),
		},
	}
	_ = params
}

func Expert(c *gin.Context) {
	content := []llms.MessageContent{
~>		llms.TextParts(llms.ChatMessageTypeSystem, "Expert in "+c.Param("field")),
		llms.TextParts(llms.ChatMessageTypeHuman, c.Query("q")),
	}
	_ = content
}
