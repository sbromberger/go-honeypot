package main

import (
	"log"
	"os"
	"strconv"

	"github.com/sbromberger/honeypot"
)

func main() {
	hp := os.Args[1]
	ports := os.Args[2]
	keyfile := os.Args[3]

	port, err := strconv.Atoi(ports)
	if err != nil {
		log.Fatal("invalid port: ", err)
	}

	s := honeypot.NewHpServer(port, keyfile, hp)
	log.Println("Starting server at ", s.Addr)
	log.Fatal(s.ListenAndServe())
}
