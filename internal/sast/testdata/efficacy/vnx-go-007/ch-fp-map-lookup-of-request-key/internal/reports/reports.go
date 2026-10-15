package reports

import (
	"net/http"
	"os"
)

var files = map[string]string{
	"monthly":   "/srv/reports/monthly.pdf",
	"quarterly": "/srv/reports/quarterly.pdf",
}

func Download(w http.ResponseWriter, r *http.Request) {
	file, ok := files[r.FormValue("report")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(file)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, "report.pdf", fi(f), f)
}
