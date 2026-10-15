package cache

import "github.com/redis/go-redis/v9"

~>const sentinelAddr = "10.40.1.9:26379"

func New() *redis.Client {
	return redis.NewClient(&redis.Options{
~>		Addr:     "10.40.1.8:6379",
		Password: "",
		DB:       0,
	})
}

~>var fallbackAddr = "10.40.1.10:6379"
