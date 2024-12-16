package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/url"
	"strings"
	"text/template"
)

type Context struct {
	Connection  *tls.Conn
	Reader      bufio.Reader
	Writer      bufio.Writer
	Certificate x509.Certificate
}

func root(c *Context) {
	t, err := template.ParseFiles("templates/root.tmpl")
	if err != nil {
		slog.Error(err.Error())
		return
	}

	_, err = c.Writer.WriteString("20 text/gemini\r\n")
	if err != nil {
		slog.Error(err.Error())
		return
	}

	err = t.Execute(&c.Writer, nil)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	err = c.Writer.Flush()
	if err != nil {
		slog.Error(err.Error())
		return
	}
}

func handleConn(conn *tls.Conn) {
	defer conn.Close()
	conn.Handshake()

	c := &Context{
		Connection:  conn,
		Reader:      *bufio.NewReader(conn),
		Writer:      *bufio.NewWriter(conn),
		Certificate: *conn.ConnectionState().PeerCertificates[0],
	}

	str, err := c.Reader.ReadString('\n')
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
