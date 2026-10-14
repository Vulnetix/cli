package cache

import "github.com/redis/go-redis/v9"

func New() *redis.Client {
	rdb := redis.NewClient(&redis.Options{
~>		Addr:     "10.20.0.7:6379",
		DB:       0,
		PoolSize: 20,
	})
	return rdb
}

func NewCluster() *redis.ClusterClient {
	return redis.NewClusterClient(&redis.ClusterOptions{
~>		Addrs: []string{"cache-0.prod.acme-corp.net:6379", "cache-1.prod.acme-corp.net:6379"},
	})
}
