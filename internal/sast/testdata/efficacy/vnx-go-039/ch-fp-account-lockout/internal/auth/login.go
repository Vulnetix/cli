package auth

import (
	"net/http"
	"time"
)

const maxFailedAttempts = 5

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	acct, err := h.store.Account(r.Context(), user)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if acct.FailedAttempts >= maxFailedAttempts && time.Since(acct.LastFailure) < 15*time.Minute {
		http.Error(w, "account locked", http.StatusTooManyRequests)
		return
	}
	if !h.check(acct, r.FormValue("password")) {
		h.store.RecordFailure(r.Context(), user)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	h.store.ResetFailures(r.Context(), user)
	h.issue(w, acct)
}
