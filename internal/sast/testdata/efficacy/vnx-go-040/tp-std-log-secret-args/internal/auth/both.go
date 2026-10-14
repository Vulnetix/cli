package auth

import "log"

func both(password, apiKey string) {
~>	log.Printf("pw=%s key=%s", password, apiKey)
}
