package main

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
)

func handleConn(c net.Conn) {
	r := bufio.NewReader(c)

	s, err := r.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	log.Println(s)
}

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.key")
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	l, err := tls.Listen("tcp", ":1965", config)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleConn(conn)
	}
}
