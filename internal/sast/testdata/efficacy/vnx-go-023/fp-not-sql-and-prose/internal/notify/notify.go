package notify

import (
	"errors"
	"log"
	"net/http"
	"os/exec"
)

// Messages, URLs and command lines that happen to contain a SQL word are not
// queries.
func Send(w http.ResponseWriter, id string, err error) {
	http.Error(w, "update env failed: "+err.Error(), http.StatusInternalServerError)
	link := "https://bodhi.fedoraproject.org/updates/?search=" + id
	log.Println("select a user from the list: " + id)
	log.Println("delete from cache where key = " + id)
	exec.Command("git", "log", "--grep=update "+id).Run()
	_ = errors.New("insert into queue failed for '" + id + "'")
	_ = link
	// q := "SELECT * FROM users WHERE id = " + id
	doc := "never write db.Query(\"SELECT * FROM users WHERE id = \" + id)"
	_ = doc
}
