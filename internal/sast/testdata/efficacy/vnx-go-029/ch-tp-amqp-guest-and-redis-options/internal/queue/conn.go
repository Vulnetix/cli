package queue

import (
	"github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

func Dial() (*amqp091.Connection, error) {
~>	return amqp091.Dial("amqp://guest:guest@localhost:5672/")
}

func Cache() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     "cache:6379",
~>		Password: "secret",
		DB:       0,
	})
}
