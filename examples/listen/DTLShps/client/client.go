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
	flag.StringVar(&host, "s", "127.0.0.1", "server `ip`")
	flag.IntVar(&port, "p", 4444, "server `port`")
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

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	startTime := time.Now()
	certificate, err := util.LoadKeyAndCertificate("../verify/cert/client.pem", "../verify/cert/client.pub.crt")
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
		RootCAs:               certPool,
		ServerName:            "server", // ServerName must be the same as 'subject: CN' in server's cert
		LoggerFactory:         logger,
	}

	// Connect to a DTLS server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	startTimeBeforeDial := time.Now()
	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, config)
	finishTime := time.Now()
	util.Check(err)
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	fmt.Printf("Total time use: %d microseconds\n", finishTime.Sub(startTime).Microseconds())
	fmt.Printf("Handshake time use: %d microseconds\n", finishTime.Sub(startTimeBeforeDial).Microseconds())
	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(dtlsConn)
}
