package obs

import (
	"context"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
)

func authed(ctx context.Context) context.Context {
	return context.WithValue(ctx, datadog.ContextAPIKeys, map[string]datadog.APIKey{
~>		"apiKeyAuth": {Key: "@@sample:[0-9a-f]{32}@@"},
~>		"appKeyAuth": {Key: "@@sample:[0-9a-f]{40}@@"},
	})
}
