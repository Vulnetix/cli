package main

import "os"

func main() {
~>	os.Setenv("AWS_BEARER_TOKEN_BEDROCK", "@@sample:ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/]{120}@@")
	run()
}
