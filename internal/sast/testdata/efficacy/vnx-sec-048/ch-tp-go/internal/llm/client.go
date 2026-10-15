package llm

import openai "github.com/sashabaranov/go-openai"

~>var client = openai.NewClient("@@sample:sk-proj-[A-Za-z0-9_-]{20}[A-Z][0-9]T3BlbkFJ[A-Za-z0-9_-]{60}@@")
