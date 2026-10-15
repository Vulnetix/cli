package main

import (
	"fmt"
	"log"
	"net"

	"github.com/labstack/echo/v4"
)

func main() {
	port := 50051
~>	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatal(err)
	}
	go grpcServer.Serve(lis)
	e := echo.New()
~>	e.Logger.Fatal(e.Start("0.0.0.0:1323"))
}
