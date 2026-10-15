package client

import (
	"errors"
	"fmt"
	"log"
	"net/http"
)

func Fetch(base, name string) (*http.Response, error) {
	u := fmt.Sprintf("%s/search?where=name='%s'", base, name)
	return http.Get(u)
}

func Fail(table, name string) error {
	log.Printf("delete from %s failed for '%s'", table, name)
	return errors.New(fmt.Sprintf("select from %s where name = '%s' returned nothing", table, name))
}
