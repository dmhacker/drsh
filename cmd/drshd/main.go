package main

import (
    "log"

	"github.com/dmhacker/drsh/internal/server"
)

func main() {
    serv, err := server.NewServer("dmhsurface", "redis://localhost:6379")
    if err != nil {
        log.Fatalln(err)
    }
    if err = serv.Start(); err != nil {
        log.Fatalln(err)
    }
    log.Println("bye")
}
