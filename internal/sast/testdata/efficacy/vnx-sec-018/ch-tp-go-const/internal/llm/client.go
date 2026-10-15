package llm

import "github.com/anthropics/anthropic-sdk-go/option"

~>const anthropicKey = "sk-ant-api03-@@sample:[A-Za-z0-9]{90}@@AA"

func opts() []option.RequestOption {
	return []option.RequestOption{option.WithAPIKey(anthropicKey)}
}
