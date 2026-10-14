package ai

import (
	"context"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

~>const palmKey = "AIza@@sample:[A-Za-z0-9]{35}@@"

func New(ctx context.Context) (*genai.Client, error) {
	return genai.NewClient(ctx, option.WithAPIKey(palmKey))
}
