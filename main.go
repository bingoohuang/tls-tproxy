package tlstproxy

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/bingoohuang/tlstproxy/dns"
	"github.com/bingoohuang/tlstproxy/plugin"
	_ "github.com/bingoohuang/tlstproxy/plugins/sanverifier"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var logger = logrus.StandardLogger()

var (
	caCertPath        string
	certPath          string
	keyPath           string
	logLevelStr       string
	portMapStr        string
	certCheckerPlugin string
)

func init() {
	fs := flag.NewFlagSet("tls-tproxy", flag.ContinueOnError)
	fs.StringVar(&caCertPath, "cacert", "", "Path to CA bundle file (PEM/X509). Uses system trust store by default.")
	fs.StringVar(&certPath, "cert", "", "Path to certificate (PEM with certificate chain).")
	fs.StringVar(&keyPath, "key", "", "Path to certificate private key (PEM with private key).")
	fs.StringVar(&logLevelStr, "logLevel", "info", fmt.Sprintf("Level to log: possible values: %v", logrus.AllLevels))
	fs.StringVar(&portMapStr, "portMap", "8443:443", "Port mapping to use, in the format of src1:dst1,src2:dst2,... "+
		"Plaintext traffic sent on port src1 will be wrapped with TLS and sent to the target IP on port dst1. The source and destination ports can be the same.")
	fs.StringVar(&certCheckerPlugin, "certCheckerPlugin", "san_verifier", "The plugin name to use for verifying certificates.")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	logLevel, err := logrus.ParseLevel(logLevelStr)
	if err != nil {
		panic(err)
	}

	logger.SetLevel(logLevel)
}

func Main() {
	portMap := make(map[uint16]uint16)
	for _, portMapPart := range strings.Split(portMapStr, ",") {
		vals := strings.SplitN(portMapPart, ":", 2)
		if len(vals) != 2 {
			logger.Panicf("Invalid portMap argument: %s", portMapStr)
		}
		src, dst := parsePortMap(vals, portMapStr)
		portMap[uint16(src)] = uint16(dst)
	}

	var caCert *x509.CertPool
	if caCertPath != "" {
		caCert = x509.NewCertPool()
		caCertBytes, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			logger.Panicf("Failed to read cacert path %s: %v", caCertPath, err)
		}
		block, rest := pem.Decode(caCertBytes)
		for block != nil {
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					logger.Panicf("Failed to parse certificate in cacert path %s: %v", caCertPath, err)
				}
				caCert.AddCert(cert)
			}
			block, rest = pem.Decode(rest)
		}
	}

	certLoader, err := NewCertificateLoader(certPath, keyPath)
	if err != nil {
		logger.Panicf("Failed to load cert/key: cert=%s, key=%s: %v", certPath, keyPath, err)
	}

	dnsCapture := dns.NewCapture(logger)
	closer, err := dnsCapture.Run()
	if err != nil {
		panic(err)
	}
	defer closer()

	var certChecker plugin.CertChecker
	for _, p := range plugin.List() {
		if p.Name() == certCheckerPlugin {
			if ccp, ok := p.(plugin.CertCheckerPlugin); ok {
				certChecker = ccp.GetCertChecker()
			} else {
				logger.Panicf("Specified certificate checker plugin "+
					"%s does not implement the CertCheckerPlugin interface: %T", certCheckerPlugin, ccp)
			}
		}
	}
	if certChecker == nil {
		logger.Panicf("Specified certificate checker plugin %s was not found.", certCheckerPlugin)
	}

	proxy := &Proxy{
		Logger:      logger,
		DnsCache:    dnsCapture.GetCache(),
		RootCAs:     caCert,
		CertLoader:  certLoader,
		CertChecker: certChecker,
		PortMap:     portMap,
	}
	stop, listenerPort, err := proxy.Run()
	if err != nil {
		panic(err)
	}
	defer stop()

	logger.Debugf("Transparent proxy listening for redirected traffic on port %d", listenerPort)

	err = SetupRedirect(logger, listenerPort, portMap)
	if err != nil {
		logger.Panicf("Failed to initialize iptables redirect of plaintext connections: %v", err)
	}
	defer func() {
		logger.Debugf("Cleaning up iptables redirect...")
		if err := CleanupRedirect(logger); err != nil {
			logger.Errorf("Error cleaning up iptables redirect: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Executing clean shutdown...")
}

func parsePortMap(vals []string, portMapStr string) (src, dst int) {
	var err error
	if src, err = strconv.Atoi(vals[0]); err != nil {
		logger.Panicf("Invalid portMap argument: %s", portMapStr)
	}
	if dst, err = strconv.Atoi(vals[1]); err != nil {
		logger.Panicf("Invalid portMap argument: %s", portMapStr)
	}
	return src, dst
}
