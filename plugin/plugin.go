package plugin

import "crypto/x509"

type Plugin interface {
	Name() string
	Init() error
}

var registeredPlugins []Plugin

func Register(plugin Plugin) {
	registeredPlugins = append(registeredPlugins, plugin)
}

func List() []Plugin {
	return registeredPlugins
}

type CertChecker func(hostnames []string, cert *x509.Certificate) error

type CertCheckerPlugin interface {
	GetCertChecker() CertChecker
}
