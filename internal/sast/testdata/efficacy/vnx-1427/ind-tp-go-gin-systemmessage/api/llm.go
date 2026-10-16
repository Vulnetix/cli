package api

import "github.com/gin-gonic/gin"

func ask(c *gin.Context) {
	topic := c.Query("topic")
	msgs := []Message{
~>		openai.SystemMessage("You are an expert on " + topic),
		openai.UserMessage("Explain."),
	}
	_ = msgs
}
