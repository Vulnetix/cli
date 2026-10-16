package aws

import (
	"context"
	"net/http"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func sign(ctx context.Context, signer *v4.Signer, creds aws.Credentials, req *http.Request, payloadHash string) error {
	err := signer.SignHTTP(ctx, creds, req, payloadHash, "execute-api", "us-east-1", time.Now())
	return err
}
