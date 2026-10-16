package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	cfg := loadConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
~>	os.WriteFile("config.export.json", data, 0o600)
~>	ioutil.WriteFile("config.bak", data, 0644)
~>	io.WriteString(os.Stdout, "exported\n")
}
