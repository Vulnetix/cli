package main

import (
	"log"
	"net/http"

	"github.com/ulule/limiter/v3"
	mhttp "github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"example.com/app/internal/auth"
)

func main() {
	rate, err := limiter.NewRateFromFormatted("5-M")
	if err != nil {
		log.Fatal(err)
	}
	mw := mhttp.NewMiddleware(limiter.New(memory.NewStore(), rate))
	mux := http.NewServeMux()
	mux.Handle("/login", mw.Handler(http.HandlerFunc(auth.Login)))
	log.Fatal(http.ListenAndServe(":8080", mux))
}
