package queue

import (
	"fmt"
	"os"

	"github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

func Dial(cfg Config) (*amqp091.Connection, error) {
	url := fmt.Sprintf("amqp://%s:%s@%s/", cfg.User, cfg.Password, cfg.Host)
	return amqp091.Dial(url)
}

func Cache() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
	})
}

const dsnTemplate = "postgres://postgres:${POSTGRES_PASSWORD}@db:5432/app"
