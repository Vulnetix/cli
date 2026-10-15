package auth

import (
	"context"
	"fmt"
	"time"
)

func fetchAccessToken(ctx context.Context, signer Signer, req *Request) (string, error) {
	err := signer.SignHTTP(ctx, req, "svc", "eu-west-1", time.Now())
	if err != nil {
		return "", fmt.Errorf("sign request: %w", err)
	}
	return req.Header.Get("X-Token"), nil
}
