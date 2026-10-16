package keys

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"time"
)

func NewAPIKey() string {
~>	seed := strconv.FormatInt(time.Now().UnixNano(), 10)
	sum := sha1.Sum([]byte(seed))
	apiKey := hex.EncodeToString(sum[:])
	return apiKey
}
