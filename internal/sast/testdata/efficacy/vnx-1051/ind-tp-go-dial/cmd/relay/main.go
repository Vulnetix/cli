package main

import (
	"net"
	"net/http"
	"github.com/go-redis/redis/v8"
)

func main() {
~>	conn, err := net.Dial("tcp", "10.30.1.6:6379")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	rdb := redis.NewClient(&redis.Options{
~>		Addr: "10.30.1.7:6379",
	})
	_ = rdb
	_, _ = http.Get("https://" + "api.internal.example.org/health")
}
