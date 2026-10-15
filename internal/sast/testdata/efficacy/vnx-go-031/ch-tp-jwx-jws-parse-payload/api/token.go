package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jws"
)

type session struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
}

func whoAmI(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
~>	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	var s session
	json.Unmarshal(msg.Payload(), &s)
	json.NewEncoder(w).Encode(s)
}
