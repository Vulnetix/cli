package blob

import "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

func newCred() (*azblob.SharedKeyCredential, error) {
	return azblob.NewSharedKeyCredential(
		"acmearchive",
~>		"@@sample:[A-Za-z0-9+/]{86}@@==",
	)
}
