package svc

import "log"

// log.Printf("password=%s", password) was removed in review
const msg = `log.Printf("token=%s", token)`

func ok() { log.Println("starting") }
