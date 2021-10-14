package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pion/logging"
	dtls "github.com/zjw1111/DTLShps"
	"github.com/zjw1111/DTLShps/examples/util"
)

func main() {
	// Parse configs
	var host string
	var port int
	var testWithoutController bool
	var skipHelloVerify bool
	var logLevel string
	flag.StringVar(&host, "s", "127.0.0.1", "listen `ip`")
	flag.IntVar(&port, "p", 4444, "listen `port`")
	flag.BoolVar(&testWithoutController, "t", false, "test program without controller")
	flag.StringVar(&logLevel, "l", "INFO", "log `level`(case insensitive): DISABLED, ERROR, WARN, INFO, DEBUG, TRACE")
	flag.BoolVar(&skipHelloVerify, "sv", false, "skip helloverify message and cookie verify")
	flag.Parse()

	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}

	// Setting log level
	var logger logging.LoggerFactory
	switch strings.ToLower(logLevel) {
	case "disabled":
		logger = &logging.DefaultLoggerFactory{DefaultLogLevel: logging.LogLevelDisabled}
	case "error":
		logger = &logging.DefaultLoggerFactory{DefaultLogLevel: logging.LogLevelError}
	case "warn":
		logger = &logging.DefaultLoggerFactory{DefaultLogLevel: logging.LogLevelWarn}
	case "debug":
		logger = &logging.DefaultLoggerFactory{DefaultLogLevel: logging.LogLevelDebug}
	case "trace":
		logger = &logging.DefaultLoggerFactory{DefaultLogLevel: logging.LogLevelTrace}
	default:
		logger = &logging.DefaultLoggerFactory{DefaultLogLevel: logging.LogLevelInfo}
	}

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
			return []byte("ABCDEF"), nil
		},
		// CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		DTLShps:               true,
		TestWithoutController: testWithoutController,
		SkipHelloVerify:       skipHelloVerify,
		Certificates:          []tls.Certificate{*certificate},
		ClientCAs:             certPool,
		LoggerFactory:         logger,
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
