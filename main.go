package main

import (
	"bufio"
	"crypto/tls"
	"log/slog"
	"net"
	"net/url"
)

func handleConn(c net.Conn) {
	r := bufio.NewReader(c)

	str, err := r.ReadString('\n')
	if err != nil {
		slog.Error(err.Error())
		return
	}

	u, err := url.Parse(str)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	println(u.Path)
}

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.key")
	if err != nil {
		slog.Error(err.Error())
		return
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	l, err := tls.Listen("tcp", ":1965", config)
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		go handleConn(conn)
	}
}
