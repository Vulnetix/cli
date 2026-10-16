package cache

import "github.com/redis/go-redis/v9"

func Dev() *redis.Client {
	return redis.NewClient(&redis.Options{Addr: "localhost:6379"})
}

func Loop() *redis.Client {
	return redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
}
