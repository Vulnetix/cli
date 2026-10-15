package cache

import "github.com/redis/go-redis/v9"

~>const redisURL = "redis://:@@sample:[A-Za-z0-9]{20}@@@redis.acme.internal:6379/0"

func New() (*redis.Client, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	return redis.NewClient(opt), nil
}
