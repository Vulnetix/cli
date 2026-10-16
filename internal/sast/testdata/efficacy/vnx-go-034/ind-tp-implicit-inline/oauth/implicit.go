package oauth

import "net/http"

func implicit(w http.ResponseWriter, r *http.Request, tok string) {
~>	http.Redirect(w, r, r.FormValue("redirect_uri")+"#access_token="+tok, http.StatusFound)
}
