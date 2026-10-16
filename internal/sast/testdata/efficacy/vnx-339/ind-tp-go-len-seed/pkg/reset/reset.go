package reset

import (
	"fmt"
	"math/rand"
)

func GenerateResetToken(username string) string {
~>	r := rand.New(rand.NewSource(int64(len(username))))
	return fmt.Sprintf("%x", r.Int63())
}
