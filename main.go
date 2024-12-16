package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

type Post struct {
	Author   string
	Creation time.Time
	Views    uint32
	Replies  []Reply
	Body     string
}

type Reply struct {
	Author   string
	Creation time.Time
	Body     string
}

type Context struct {
	URL         url.URL
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

func viewPost(c *Context) {
	split := strings.Split(c.URL.Path, "/")
	id := split[len(split)-1]

	file, err := os.Open("posts/" + id)
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer file.Close()

	post := &Post{}
	err = gob.NewDecoder(file).Decode(post)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	t, err := template.ParseFiles("templates/post.tmpl")
	if err != nil {
		slog.Error(err.Error())
		return
	}

	_, err = c.Writer.WriteString("20 text/gemini\r\n")
	if err != nil {
		slog.Error(err.Error())
		return
	}

	err = t.Execute(&c.Writer, post)
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

func submitPost(c *Context) {
	if c.URL.RawQuery == "" {
		_, err := c.Writer.WriteString("10 Enter post body\r\n")
		if err != nil {
			slog.Error(err.Error())
			return
		}

		err = c.Writer.Flush()
		if err != nil {
			slog.Error(err.Error())
			return
		}

		return
	}

	body, err := url.QueryUnescape(c.URL.RawQuery)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	post := &Post{
		Author:   c.Certificate.Issuer.CommonName,
		Creation: time.Now().UTC(),
		Views:    0,
		Replies:  make([]Reply, 0),
		Body:     body,
	}

	id, err := gonanoid.New()
	if err != nil {
		slog.Error(err.Error())
		return
	}

	file, err := os.Create("posts/" + id)
	if err != nil {
		slog.Error(err.Error())
		return
	}
	defer file.Close()

	err = gob.NewEncoder(file).Encode(post)
	if err != nil {
		slog.Error(err.Error())
		return
	}

	_, err = c.Writer.WriteString("30 /post/" + id + "\r\n")
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
	c.URL = *u

	if strings.HasPrefix(u.Path, "/post/") {
		viewPost(c)
		return
	}

	switch u.Path {
	case "/":
		root(c)
	case "/submit":
		submitPost(c)
	}
}

func main() {
	_, err := os.Stat("posts")
	if errors.Is(err, os.ErrNotExist) {
		os.Mkdir("posts", fs.ModeDir)
		slog.Info("made posts directory")
	}

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

		go func() {
			handleConn(conn.(*tls.Conn))
		}()
	}
}
