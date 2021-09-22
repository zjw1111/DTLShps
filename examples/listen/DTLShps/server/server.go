package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	dtls "github.com/zjw1111/DTLShps"
	"github.com/zjw1111/DTLShps/examples/util"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Create parent context to cleanup handshaking connections on exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	certificate, err := util.LoadKeyAndCertificate("../verify/cert/server.pem", "../verify/cert/server.pub.crt")
	util.Check(err)

	rootCertificate, err := util.LoadCertificate("../verify/cert/CA.crt")
	util.Check(err)
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	util.Check(err)
	certPool.AddCert(cert)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			fmt.Printf("Client's hint: %s \n", hint)
			return []byte{0xAB, 0xC1, 0x23}, nil
		},
		// PSKIdentityHint:      []byte("Pion DTLS Client"),
		// CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		DTLShps:               true,
		TestWithoutController: true,
		Certificates:          []tls.Certificate{*certificate},
		ClientAuth:            dtls.RequireAndVerifyClientCert,
		ClientCAs:             certPool,
		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
	}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close())
	}()

	fmt.Println("Listening")

	// Simulate a chat session
	hub := util.NewHub()

	go func() {
		for {
			// Wait for a connection.
			conn, err := listener.Accept()
			util.Check(err)
			// defer conn.Close() // TODO: graceful shutdown

			// `conn` is of type `net.Conn` but may be casted to `dtls.Conn`
			// using `dtlsConn := conn.(*dtls.Conn)` in order to to expose
			// functions like `ConnectionState` etc.

			// Register the connection with the chat hub
			if err == nil {
				hub.Register(conn)
			}
		}
	}()

	// Start chatting
	hub.Chat()
}
