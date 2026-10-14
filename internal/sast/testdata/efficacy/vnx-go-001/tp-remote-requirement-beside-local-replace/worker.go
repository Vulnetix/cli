package main

import (
	"context"

	"github.com/acme/monorepo/libs/queue"
	"github.com/redis/go-redis/v9"
)

func main() {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	queue.Run(context.Background(), rdb)
}
