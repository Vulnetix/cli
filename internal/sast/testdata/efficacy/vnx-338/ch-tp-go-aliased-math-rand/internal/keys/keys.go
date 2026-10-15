package keys

import (
	"fmt"
	mrand "math/rand"
)

func NewAPIKey() string {
~>	apiKey := fmt.Sprintf("%x%x", mrand.Int63(), mrand.Int63())
	return apiKey
}
