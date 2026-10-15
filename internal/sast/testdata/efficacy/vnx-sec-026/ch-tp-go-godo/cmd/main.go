package main

import "github.com/digitalocean/godo"

func main() {
~>	client := godo.NewFromToken("dop_v1_@@sample:[a-f0-9]{64}@@")
	_ = client
}
