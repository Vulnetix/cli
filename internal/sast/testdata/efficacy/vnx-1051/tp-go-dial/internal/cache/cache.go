package cache

import (
	"net"

	"github.com/redis/go-redis/v9"
)

func NewClient() *redis.Client {
	return redis.NewClient(&redis.Options{
~>		Addr: "10.30.1.5:6379",
		DB:   0,
	})
}

func Ping() error {
~>	conn, err := net.Dial("tcp", "10.30.1.6:6379")
	if err != nil {
		return err
	}
	return conn.Close()
}
