package report

import (
	"errors"
	"fmt"
	"log"
	"net/url"
)

type Cache interface{ Get(key string) (string, bool) }

// SQL-looking text that never reaches a database.
func Explain(user string, c Cache, u *url.URL) error {
	log.Printf("SELECT failed for user = '%s'", user)
	if v, ok := c.Get(fmt.Sprintf("user = '%s'", user)); ok {
		log.Println(v)
	}
	q := u.Query()
	q.Set("from", user)
	// db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user)) was
	// replaced by the parameterised form.
	hint := `db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user))`
	return errors.New(fmt.Sprintf("bad query for %s: %s", user, hint))
}
