package sanverifier

import (
	"crypto/x509"
	"fmt"
	"github.com/bingoohuang/tlstproxy/plugin"
)

type Plugin struct{}

func init() {
	plugin.Register(&Plugin{})
}

func (p *Plugin) Name() string { return "san_verifier" }

func (p *Plugin) Init() error { return nil }

func (p *Plugin) GetCertChecker() plugin.CertChecker {
	return func(hostnames []string, cert *x509.Certificate) error {
		for _, hostname := range hostnames {
			if err := cert.VerifyHostname(hostname); err == nil {
				return nil
			}
		}
		return fmt.Errorf("none of the expected hostnames were in the certificate: %v", hostnames)
	}
}
