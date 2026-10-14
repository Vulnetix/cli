package blob

import "github.com/aws/aws-sdk-go/aws/credentials"

~>var creds = credentials.NewStaticCredentials(keyID, "@@sample:[A-Za-z0-9/+]{40}@@", "")
