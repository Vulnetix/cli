package cache

import "github.com/redis/go-redis/v9"

func New() *redis.Client {
	return redis.NewClient(&redis.Options{
~>		Addr:     "10.20.0.7:6379",
		Password: "",
		DB:       0,
	})
}
