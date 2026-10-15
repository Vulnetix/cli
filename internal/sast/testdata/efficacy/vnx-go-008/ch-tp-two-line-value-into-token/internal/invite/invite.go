package invite

import (
	"math/rand"
	"strconv"
)

type Invite struct{ Token string }

func Issue(email string) Invite {
~>	n := rand.Int63()
	token := strconv.FormatInt(n, 36)
	return Invite{Token: token}
}
