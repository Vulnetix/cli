package store

import (
	"crypto/tls"
	"net/smtp"

	"github.com/IBM/sarama"
	"github.com/redis/go-redis/v9"
)

func Kafka(brokers []string) (sarama.Client, error) {
	cfg := sarama.NewConfig()
	cfg.Net.TLS.Enable = true
	cfg.Net.TLS.Config = &tls.Config{
		MinVersion:            tls.VersionTLS12,
~>		InsecureSkipVerify:    true,
		VerifyPeerCertificate: nil,
	}
	return sarama.NewClient(brokers, cfg)
}

func Cache(addr string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr: addr,
~>		TLSConfig: &tls.Config{ InsecureSkipVerify : true },
	})
}

func Mail(host string) (*smtp.Client, error) {
	c, err := smtp.Dial(host + ":587")
	if err != nil {
		return nil, err
	}
~>	return c, c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true})
}
