package authz

import (
	"fmt"
	"net/http"
)

func (h *Handler) Token(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cb := req.Form.Get("redirect_uri")
	tok := h.mint(req.Form.Get("client_id"))
~>	w.Header().Set("Location", fmt.Sprintf("%s#access_token=%s&token_type=bearer", cb, tok))
	w.WriteHeader(http.StatusFound)
}
