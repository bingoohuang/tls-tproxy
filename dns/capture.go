package dns

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

type Capture struct {
	activeQuestions map[uint16][]string
	cache           *Cache
	logger          *logrus.Logger
}

func NewCapture(logger *logrus.Logger) *Capture {
	return &Capture{
		activeQuestions: make(map[uint16][]string),
		cache:           NewCache(),
		logger:          logger,
	}
}

func (c *Capture) GetCache() *Cache { return c.cache }

func (c *Capture) Run() (func(), error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("unable to enumerate all pcap interfaces: %v", err)
	}
	localIps := make([]net.IP, 0)
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			localIps = append(localIps, addr.IP)
		}
	}

	handle, err := pcap.OpenLive("any", 65535, false, 1*time.Second)
	if err != nil {
		return nil, err
	}
	err = handle.SetBPFFilter("udp port 53")
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer c.logger.Infof("DNS packet capture shutting down...")

		for {
			packet, err := packetSource.NextPacket()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			} else if err == io.EOF {
				return
			} else if err != nil {
				c.logger.Errorf("Got error retrieving packet: %v", err)
				continue
			}
			if err := c.handlePacket(localIps, packet); err != nil {
				c.logger.Errorf("Got error handling packet: %v", err)
				continue
			}
		}
	}()

	return func() { handle.Close(); wg.Wait() }, nil
}

func contains(haystack []string, needle string) bool {
	for _, val := range haystack {
		if val == needle {
			return true
		}
	}
	return false
}

func (c *Capture) handlePacket(localIps []net.IP, packet gopacket.Packet) error {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil
	}

	src := net.IP(networkLayer.NetworkFlow().Src().Raw())
	dst := net.IP(networkLayer.NetworkFlow().Dst().Raw())

	isIncoming, isOutgoing := parseDirection(localIps, src, dst)
	if !isIncoming && !isOutgoing {
		c.logger.Tracef("Saw packet with neither src nor dst matching a local IP: %s => %s", src.String(), dst.String())
		return nil
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		if dns, ok := dnsLayer.(*layers.DNS); ok {
			if isOutgoing {
				c.handlerOutgoingDnsPacket(dns)
			} else if isIncoming {
				c.handlerIncomingDnsPacket(dns)
			}
		}
	}

	return nil
}

func anyOf(typ layers.DNSType, targets ...layers.DNSType) bool {
	for _, target := range targets {
		if typ == target {
			return true
		}
	}

	return false
}

func (c *Capture) handlerIncomingDnsPacket(dns *layers.DNS) {
	validQuestions := c.activeQuestions[dns.ID][:]
	for _, answer := range dns.Answers {
		if answer.Class == layers.DNSClassIN && anyOf(answer.Type, layers.DNSTypeCNAME, layers.DNSTypeA, layers.DNSTypeAAAA) {
			name := string(answer.Name)
			if !contains(validQuestions, name) {
				c.logger.Warnf("Saw unexpected DNS response for name=%s", name)
				continue
			}

			expiry := time.Now().Add(time.Duration(answer.TTL) * time.Second)
			var resolved string
			if answer.Type == layers.DNSTypeCNAME {
				resolved = string(answer.CNAME)
				validQuestions = append(validQuestions, resolved)
			} else if anyOf(answer.Type, layers.DNSTypeA, layers.DNSTypeAAAA) {
				resolved = answer.IP.String()
			}

			c.logger.Tracef("Adding DNS resolution %s => %s (expiry=%s)", name, resolved, expiry)
			c.cache.AddAlias(name, resolved, expiry)
		}
	}
}

func (c *Capture) handlerOutgoingDnsPacket(dns *layers.DNS) {
	questions := make([]string, 0, len(dns.Questions))
	for _, question := range dns.Questions {
		if anyOf(question.Type, layers.DNSTypeA, layers.DNSTypeAAAA) && question.Class == layers.DNSClassIN {
			name := string(question.Name)
			logrus.Tracef("Saw query for name: %s", name)
			questions = append(questions, name)
		}
	}
	c.activeQuestions[dns.ID] = questions
}

func parseDirection(localIps []net.IP, src, dst net.IP) (isIncoming, isOutgoing bool) {
	for _, ip := range localIps {
		if bytes.Equal(ip, src) {
			isOutgoing = true
			break
		}
		if bytes.Equal(ip, dst) {
			isIncoming = true
			break
		}
	}
	return
}
