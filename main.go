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
	errorUtil(err)

	_, err = c.Writer.WriteString("20 text/gemini\r\n")
	errorUtil(err)

	err = t.Execute(&c.Writer, nil)
	errorUtil(err)

	err = c.Writer.Flush()
	errorUtil(err)
}

func viewPost(c *Context) {
	split := strings.Split(c.URL.Path, "/")
	id := split[len(split)-1]

	file, err := os.Open("posts/" + id)
	errorUtil(err)
	defer file.Close()

	post := &Post{}
	err = gob.NewDecoder(file).Decode(post)
	errorUtil(err)

	t, err := template.ParseFiles("templates/post.tmpl")
	errorUtil(err)

	_, err = c.Writer.WriteString("20 text/gemini\r\n")
	errorUtil(err)

	err = t.Execute(&c.Writer, post)
	errorUtil(err)

	err = c.Writer.Flush()
	errorUtil(err)
}

func submitPost(c *Context) {
	if c.URL.RawQuery == "" {
		_, err := c.Writer.WriteString("10 Enter post body\r\n")
		errorUtil(err)

		err = c.Writer.Flush()
		errorUtil(err)

		return
	}

	body, err := url.QueryUnescape(c.URL.RawQuery)
	errorUtil(err)

	post := &Post{
		Author:   c.Certificate.Issuer.CommonName,
		Creation: time.Now().UTC(),
		Views:    0,
		Replies:  make([]Reply, 0),
		Body:     body,
	}

	id, err := gonanoid.New()
	errorUtil(err)

	file, err := os.Create("posts/" + id)
	errorUtil(err)
	defer file.Close()

	err = gob.NewEncoder(file).Encode(post)
	errorUtil(err)

	_, err = c.Writer.WriteString("30 /post/" + id + "\r\n")
	errorUtil(err)

	err = c.Writer.Flush()
	errorUtil(err)
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
	errorUtil(err)
	str = strings.TrimSuffix(str, "\r\n")

	u, err := url.Parse(str)
	errorUtil(err)
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
