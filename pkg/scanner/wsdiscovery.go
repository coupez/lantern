package scanner

import (
	"context"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	wsdSOAP                 = "http://www.w3.org/2003/05/soap-envelope"
	onvifDiscoveryReference = "https://www.onvif.org/specs/core/ONVIF-Core-Specification-v1912.pdf"
	maxWSDBytes             = 65507
)

type wsdVersion struct{ discovery, addressing, to, anonymous, profile string }

var wsdVersions = []wsdVersion{
	{"http://schemas.xmlsoap.org/ws/2005/04/discovery", "http://schemas.xmlsoap.org/ws/2004/08/addressing", "urn:schemas-xmlsoap-org:ws:2005:04:discovery", "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous", "http://schemas.xmlsoap.org/ws/2006/02/devprof"},
	{"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01", "http://www.w3.org/2005/08/addressing", "urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01", "http://www.w3.org/2005/08/addressing/anonymous", "http://docs.oasis-open.org/ws-dd/ns/dpws/2009/01"},
}

type wsdProbe struct {
	id      string
	version wsdVersion
	packet  []byte
}

func newWSDProbes() ([]wsdProbe, error) {
	var probes []wsdProbe
	for _, version := range wsdVersions {
		for _, typed := range []bool{false, true} {
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				return nil, err
			}
			id[6] = id[6]&0x0f | 0x40
			id[8] = id[8]&0x3f | 0x80
			messageID := fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
			// Keep broad discovery and also query DPWS Device explicitly: some
			// deployed hosts (including wsdd 0.7) ignore untyped Probes.
			types := ""
			if typed {
				types = "<d:Types>wsdp:Device</d:Types>"
			}
			packet := fmt.Sprintf(`<s:Envelope xmlns:s="%s" xmlns:a="%s" xmlns:d="%s" xmlns:wsdp="%s"><s:Header><a:Action>%s/Probe</a:Action><a:MessageID>%s</a:MessageID><a:To>%s</a:To><a:ReplyTo><a:Address>%s</a:Address></a:ReplyTo></s:Header><s:Body><d:Probe>%s</d:Probe></s:Body></s:Envelope>`, wsdSOAP, version.addressing, version.discovery, version.profile, version.discovery, messageID, version.to, version.anonymous, types)
			probes = append(probes, wsdProbe{messageID, version, []byte(packet)})
		}
	}
	return probes, nil
}

func wsdSweepOn(ctx context.Context, target netip.Prefix, timeout time.Duration, preferred string) ([]discoveryHit, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	c, iface, local, closeSocket, err := openMulticastSocket(ctx, target, preferred, timeout)
	if err != nil {
		return nil, discoveryCompletion(ctx, "WS-Discovery", err, 0, 0)
	}
	if iface == nil {
		return nil, nil
	}
	defer closeSocket()
	destination := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 3702}
	if local.Is6() {
		destination = &net.UDPAddr{IP: net.ParseIP("ff02::c"), Port: 3702, Zone: iface.Name}
		err = ipv6.NewPacketConn(c).SetMulticastHopLimit(1)
	} else {
		err = ipv4.NewPacketConn(c).SetMulticastTTL(1)
	}
	if err != nil {
		return nil, discoveryCompletion(ctx, "WS-Discovery", fmt.Errorf("WS-Discovery hop limit: %w", err), 0, 0)
	}
	probes, err := newWSDProbes()
	if err != nil {
		return nil, err
	}
	return collectWSD(ctx, c, destination, target, iface.Name, probes)
}

type wsdUDPConn interface {
	discoveryUDPConn
	SetWriteDeadline(time.Time) error
}

func collectWSD(ctx context.Context, c wsdUDPConn, destination *net.UDPAddr, target netip.Prefix, zone string, probes []wsdProbe) ([]discoveryHit, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	// The owner sets the receive deadline and closes the socket on cancellation.
	// Retransmissions run concurrently with reception and are joined on return.
	sendCtx, stop := context.WithCancel(ctx)
	sendDone := make(chan error, 1)
	send := func() error {
		for _, probe := range probes {
			if sendCtx.Err() != nil {
				return nil
			}
			if err := c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
				return err
			}
			if err := writeDiscoveryDatagram(c, probe.packet, destination); err != nil {
				return fmt.Errorf("WS-Discovery query: %w", err)
			}
		}
		return nil
	}
	if err := send(); err != nil {
		stop()
		return nil, discoveryCompletion(ctx, "WS-Discovery", err, 0, 0)
	}
	go func() {
		// SOAP-over-UDP: two repeats, randomized initial 50–250 ms delay,
		// then exponential backoff. Each retransmission keeps its MessageID.
		jitter, err := rand.Int(rand.Reader, big.NewInt(201))
		if err != nil {
			sendDone <- err
			return
		}
		delay := time.Duration(50+jitter.Int64()) * time.Millisecond
		for range 2 {
			timer := time.NewTimer(delay)
			select {
			case <-sendCtx.Done():
				timer.Stop()
				sendDone <- nil
				return
			case <-timer.C:
			}
			if err := send(); err != nil {
				sendDone <- err
				return
			}
			delay *= 2
		}
		sendDone <- nil
	}()
	hits := []discoveryHit{}
	type responseKey struct {
		ip                netip.Addr
		endpoint, message string
	}
	seen := map[responseKey]bool{}
	packets := 0
	finish := func(err error) ([]discoveryHit, error) {
		stop()
		return hits, discoveryCompletion(ctx, "WS-Discovery", errors.Join(err, <-sendDone), packets, 0)
	}
	b := make([]byte, maxWSDBytes+1)
	for packets < maxDiscoveryPackets && ctx.Err() == nil {
		n, peer, err := c.ReadFromUDP(b)
		if err != nil {
			return finish(discoveryReceiveError("WS-Discovery", err))
		}
		packets++
		if peer == nil || n > maxWSDBytes {
			continue
		}
		ip, ok := netip.AddrFromSlice(peer.IP)
		ip = ip.Unmap()
		if !ok || ip.IsUnspecified() || ip.IsMulticast() || !inTarget(target, ip) || (peer.Zone != "" && peer.Zone != zone) {
			continue
		}
		ads, err := parseWSD(b[:n], probes)
		if err != nil {
			continue
		}
		for _, ad := range ads {
			// Identical retransmissions cannot multiply advertisements or work.
			key := responseKey{ip, ad.Instance, ad.Properties["message_id"]}
			if seen[key] {
				continue
			}
			seen[key] = true
			names := []string{}
			for _, scope := range strings.Fields(ad.Properties["scopes"]) {
				if field, value := onvifScope(scope); field == "name" {
					names = append(names, value)
				}
			}
			hits = append(hits, discoveryHit{IP: scoped(ip, zone), Names: names, Ads: []Advertisement{ad}, Evidence: "ws-discovery"})
		}
	}
	return finish(nil)
}

// A bounded XML tree preserves expanded element names and in-scope namespaces
// for QName-valued Types. No schema fetching, entities, or external resources.
type wsdNode struct {
	name       xml.Name
	text       string
	namespaces map[string]string
	children   []*wsdNode
}

func readWSDXML(b []byte) (*wsdNode, error) {
	if len(b) > maxWSDBytes {
		return nil, errors.New("WS-Discovery datagram too large")
	}
	decoder := xml.NewDecoder(strings.NewReader(string(b)))
	var root *wsdNode
	var stack []*wsdNode
	count := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch v := token.(type) {
		case xml.StartElement:
			count++
			if len(stack) >= 16 || count > 512 || len(v.Attr) > 64 {
				return nil, errors.New("WS-Discovery XML budget exceeded")
			}
			node := &wsdNode{name: v.Name, namespaces: map[string]string{}}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
				for k, v := range parent.namespaces {
					node.namespaces[k] = v
				}
			} else {
				if root != nil {
					return nil, errors.New("multiple XML roots")
				}
				root = node
			}
			attributes := map[xml.Name]bool{}
			for _, a := range v.Attr {
				if attributes[a.Name] {
					return nil, errors.New("duplicate XML attribute")
				}
				attributes[a.Name] = true
				if a.Name.Space == "xmlns" {
					node.namespaces[a.Name.Local] = a.Value
				}
				if a.Name.Space == "" && a.Name.Local == "xmlns" {
					node.namespaces[""] = a.Value
				}
			}
			if len(node.namespaces) > 64 {
				return nil, errors.New("too many XML namespaces")
			}
			stack = append(stack, node)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(v)) != "" {
					return nil, errors.New("text outside XML root")
				}
				continue
			}
			node := stack[len(stack)-1]
			if len(node.text)+len(v) > 8192 {
				return nil, errors.New("WS-Discovery field too large")
			}
			node.text += string(v)
		case xml.Directive:
			return nil, errors.New("XML directives are unsupported")
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errors.New("incomplete XML")
	}
	return root, nil
}
func (n *wsdNode) child(space, local string, required bool) (*wsdNode, error) {
	if strings.TrimSpace(n.text) != "" {
		return nil, errors.New("unexpected text in WS-Discovery structure")
	}
	var found *wsdNode
	for _, c := range n.children {
		if c.name == (xml.Name{Space: space, Local: local}) {
			if found != nil {
				return nil, fmt.Errorf("duplicate WS-Discovery %s", local)
			}
			found = c
		}
	}
	if found == nil && required {
		return nil, fmt.Errorf("missing WS-Discovery %s", local)
	}
	return found, nil
}
func (n *wsdNode) value(space, local string, required bool) (string, error) {
	c, err := n.child(space, local, required)
	if err != nil || c == nil {
		return "", err
	}
	if len(c.children) != 0 {
		return "", errors.New("nested WS-Discovery field")
	}
	value := strings.TrimSpace(c.text)
	if required && value == "" {
		return "", fmt.Errorf("empty WS-Discovery %s", local)
	}
	return value, nil
}
func parseWSD(b []byte, probes []wsdProbe) ([]Advertisement, error) {
	root, err := readWSDXML(b)
	if err != nil {
		return nil, err
	}
	if root.name != (xml.Name{Space: wsdSOAP, Local: "Envelope"}) {
		return nil, errors.New("expected SOAP 1.2 envelope")
	}
	header, err := root.child(wsdSOAP, "Header", true)
	if err != nil {
		return nil, err
	}
	body, err := root.child(wsdSOAP, "Body", true)
	if err != nil {
		return nil, err
	}
	for _, probe := range probes {
		v := probe.version
		action, err := header.value(v.addressing, "Action", true)
		if err != nil {
			continue
		}
		relation, err := header.value(v.addressing, "RelatesTo", true)
		if err != nil {
			continue
		}
		if action != v.discovery+"/ProbeMatches" || relation != probe.id {
			continue
		}
		message, err := header.value(v.addressing, "MessageID", true)
		if err != nil {
			return nil, err
		}
		if !wsdAbsoluteURI(message) {
			return nil, errors.New("invalid WS-Discovery MessageID")
		}
		matches, err := body.child(v.discovery, "ProbeMatches", true)
		if err != nil {
			return nil, err
		}
		var ads []Advertisement
		matchCount := 0
		for _, match := range matches.children {
			if match.name != (xml.Name{Space: v.discovery, Local: "ProbeMatch"}) {
				continue
			}
			matchCount++
			if matchCount > 32 {
				return nil, errors.New("too many WS-Discovery matches")
			}
			endpoint, err := match.child(v.addressing, "EndpointReference", true)
			if err != nil {
				return nil, err
			}
			address, err := endpoint.value(v.addressing, "Address", true)
			if err != nil {
				return nil, err
			}
			if !wsdAbsoluteURI(address) {
				return nil, errors.New("invalid WS-Discovery endpoint address")
			}
			props := map[string]string{"message_id": message, "discovery_namespace": v.discovery}
			for _, f := range []struct{ tag, key string }{{"Scopes", "scopes"}, {"XAddrs", "xaddrs"}, {"MetadataVersion", "metadata_version"}} {
				value, err := match.value(v.discovery, f.tag, f.tag == "MetadataVersion")
				if err != nil {
					return nil, err
				}
				if f.tag == "MetadataVersion" {
					if _, err := strconv.ParseUint(value, 10, 32); err != nil {
						return nil, err
					}
				}
				if len(strings.Fields(value)) > 64 {
					return nil, errors.New("too many WS-Discovery field values")
				}
				if value != "" {
					props[f.key] = value
				}
			}
			types, err := match.value(v.discovery, "Types", false)
			if err != nil {
				return nil, err
			}
			typesNode, _ := match.child(v.discovery, "Types", false)
			expanded := []string{}
			for _, qname := range strings.Fields(types) {
				prefix, local, hasPrefix := strings.Cut(qname, ":")
				if !hasPrefix {
					local, prefix = prefix, ""
				}
				ns, ok := typesNode.namespaces[prefix]
				if (hasPrefix && (!ok || ns == "")) || !wsdLocalName(local) || strings.ContainsAny(ns, "{} \t\r\n") {
					return nil, errors.New("invalid discovery type QName")
				}
				expanded = append(expanded, "{"+ns+"}"+local)
			}
			if len(expanded) > 64 {
				return nil, errors.New("too many discovery types")
			}
			sort.Strings(expanded)
			if contains(expanded, "{"+v.discovery+"}DiscoveryProxy") {
				continue
			}
			if len(expanded) > 0 {
				props["types"] = strings.Join(expanded, " ")
			}
			ads = append(ads, Advertisement{Protocol: "ws-discovery", Service: "probe-match", Instance: address, Properties: props})
		}
		return ads, nil
	}
	return nil, errors.New("uncorrelated WS-Discovery response")
}

func wsdAbsoluteURI(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.IsAbs() && len(value) <= 2048 && !strings.ContainsAny(value, " \t\r\n")
}

func wsdLocalName(value string) bool {
	if value == "" || strings.ContainsAny(value, ":<>&/\"'= \t\r\n") {
		return false
	}
	// Let the XML parser apply XML's Unicode name rules, rather than an ASCII
	// approximation that rejects valid names or accepts invalid QName text.
	token, err := xml.NewDecoder(strings.NewReader("<" + value + "/>")).Token()
	start, ok := token.(xml.StartElement)
	return err == nil && ok && start.Name.Local == value && start.Name.Space == ""
}

func onvifScope(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "onvif" || !strings.EqualFold(u.Host, "www.onvif.org") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", ""
	}
	for _, field := range []string{"name", "hardware"} {
		prefix := "/" + field + "/"
		if strings.HasPrefix(u.EscapedPath(), prefix) {
			value, err := url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), prefix))
			if err == nil && value != "" && len(value) <= 2048 && CleanText(value) == value {
				return field, value
			}
		}
	}
	return "", ""
}
