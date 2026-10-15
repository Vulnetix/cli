package web

import "net/http"

func AddToCart(w http.ResponseWriter, r *http.Request) {
	// ... add the item, then send the shopper back where they came from
~>	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

func RemoveFromCart(w http.ResponseWriter, r *http.Request) {
	back := r.Header.Get("Referer")
~>	w.Header().Set("Location", back)
	w.WriteHeader(http.StatusSeeOther)
}
