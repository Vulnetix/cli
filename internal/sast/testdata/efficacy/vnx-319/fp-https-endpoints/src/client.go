package src

import "net/http"

const apiURL = "https://api.partner-corp.net/v1"

func get() { http.Get("https://status.cloud-vendor.io/health"); http.Get("http://localhost:8080/health") }
