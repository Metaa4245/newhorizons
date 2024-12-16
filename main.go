package main

import (
	"bufio"
	"crypto/tls"
	"log/slog"
	"net/url"
	"strings"
)

func root(c *tls.Conn) {

}

func handleConn(c *tls.Conn) {
	c.Handshake()
	r := bufio.NewReader(c)

	str, err := r.ReadString('\n')
	if err != nil {
		slog.Error(err.Error())
		return
	}
	str = strings.TrimSuffix(str, "\r\n")

	u, err := url.Parse(str)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	switch u.Path {
	case "/":
		root(c)
	}
}

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.key")
	if err != nil {
		slog.Error(err.Error())
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
	}

	l, err := tls.Listen("tcp", ":1965", config)
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer l.Close()
	slog.Info("listening on 127.0.0.1:1965")

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		go handleConn(conn.(*tls.Conn))
	}
}
