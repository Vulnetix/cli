package s3

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
)

func creds(keyID string) *credentials.Credentials {
~>	return credentials.NewStaticCredentials(keyID, "@@sample:[A-Za-z0-9/+]{40}@@", "")
}
