package tlstproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/bingoohuang/tlstproxy/dns"
	"github.com/bingoohuang/tlstproxy/plugin"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

type Proxy struct {
	Logger      *logrus.Logger
	DnsCache    *dns.Cache
	RootCAs     *x509.CertPool
	CertLoader  *CachedCertificateLoader
	CertChecker plugin.CertChecker
	PortMap     map[uint16]uint16
}

func (p *Proxy) Run() (stop func(), listenerPort int, err error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, 0, err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer p.Logger.Infof("Proxy shutting down...")

		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				p.Logger.Errorf("Got error accepting connection: %v", err)
				continue
			}
			go p.handleConn(conn)
		}
	}()

	listenerPort = listener.Addr().(*net.TCPAddr).Port

	return func() { listener.Close(); wg.Wait() }, listenerPort, nil
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		p.Logger.Errorf("Got non-TCP connection: %T", conn)
		return
	}
	ipv4, port, err := getOriginalDst(tcpConn)
	if err != nil {
		p.Logger.Errorf("Unable to resolve original destination of connection: %v", err)
		return
	}
	targetPort := p.PortMap[port]
	if targetPort == 0 {
		p.Logger.Errorf("Unexpect original target port: %d", port)
		return
	}

	hostnames := p.DnsCache.GetAliases(ipv4)
	if len(hostnames) == 0 {
		// Wait 1 second for captured packets to make their way into the DNS cache...
		time.Sleep(1 * time.Second)

		hostnames = p.DnsCache.GetAliases(ipv4)
		if len(hostnames) == 0 {
			p.Logger.Errorf("Found no DNS lookups for target IP %s", ipv4)
			return
		}
	}
	p.Logger.Tracef("Found DNS lookups for IP %s => %v", ipv4, hostnames)

	tlsConfig := &tls.Config{
		RootCAs:            p.RootCAs,
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return p.CertLoader.GetCertificate()
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Based on the golang verification code. See https://golang.org/src/crypto/tls/handshake_client.go
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("proxy: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}

			opts := x509.VerifyOptions{
				Roots:         p.RootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err := certs[0].Verify(opts); err != nil {
				return err
			}

			if err = p.CertChecker(hostnames, certs[0]); err != nil {
				return err
			}

			return nil
		},
	}

	targetConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", ipv4, targetPort), tlsConfig)
	if err != nil {
		p.Logger.Errorf("Failed to dial target %s:%d: %v", ipv4, targetPort, err)
		return
	}

	// Copy data between the two connections
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() { io.Copy(targetConn, conn); wg.Done() }()
	io.Copy(conn, targetConn)
	wg.Wait()
}
