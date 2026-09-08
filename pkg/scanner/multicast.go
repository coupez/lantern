package scanner

import (
	"context"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Advertisement is device-reported discovery data, not a verified open port.
type Advertisement struct {
	Protocol   string            `json:"protocol"`
	Instance   string            `json:"instance,omitempty"`
	Service    string            `json:"service,omitempty"`
	Port       uint16            `json:"port,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}
type discoveryHit struct {
	IP       netip.Addr
	Names    []string
	Ads      []Advertisement
	Evidence string
}
type mdnsRecords struct {
	addresses map[string][]netip.Addr
	services  map[string]dnsmessage.SRVResource
	txt       map[string]map[string]string
}

func newMDNSRecords() *mdnsRecords {
	return &mdnsRecords{map[string][]netip.Addr{}, map[string]dnsmessage.SRVResource{}, map[string]map[string]string{}}
}
func (r *mdnsRecords) ingest(b []byte) bool {
	var m dnsmessage.Message
	if m.Unpack(b) != nil || !m.Header.Response {
		return false
	}
	records := append(m.Answers, m.Additionals...)
	for _, rr := range records {
		if rr.Header.TTL == 0 {
			continue
		}
		name := strings.ToLower(rr.Header.Name.String())
		switch v := rr.Body.(type) {
		case *dnsmessage.AResource:
			a := netip.AddrFrom4(v.A)
			exists := false
			for _, old := range r.addresses[name] {
				if old == a {
					exists = true
				}
			}
			if !exists {
				r.addresses[name] = append(r.addresses[name], a)
			}
		case *dnsmessage.SRVResource:
			r.services[name] = *v
		case *dnsmessage.TXTResource:
			props := map[string]string{}
			for _, s := range v.TXT {
				key, value, _ := strings.Cut(s, "=")
				props[CleanText(key)] = CleanText(value)
			}
			r.txt[name] = props
		}
	}
	return true
}
func (r *mdnsRecords) hits(target netip.Prefix) []discoveryHit {
	out := []discoveryHit{}
	for name, ips := range r.addresses {
		for _, ip := range ips {
			if !target.Contains(ip) {
				continue
			}
			h := discoveryHit{IP: ip, Names: []string{strings.TrimSuffix(name, ".")}, Evidence: "mdns"}
			for instance, srv := range r.services {
				if !strings.EqualFold(srv.Target.String(), name) {
					continue
				}
				kind := ""
				if i := strings.Index(instance, "._"); i >= 0 {
					kind = strings.TrimSuffix(instance[i+1:], ".local.")
				}
				h.Ads = append(h.Ads, Advertisement{Protocol: "mdns", Instance: strings.TrimSuffix(instance, "."), Service: kind, Port: srv.Port, Properties: r.txt[instance]})
			}
			out = append(out, h)
		}
	}
	return out
}
func multicastSocket(ctx context.Context, local netip.Addr, iface *net.Interface, timeout time.Duration) (*net.UDPConn, func(), error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(local.AsSlice())})
	if err != nil {
		return nil, nil, err
	}
	pc := ipv4.NewPacketConn(c)
	if err = pc.SetMulticastInterface(iface); err != nil {
		c.Close()
		return nil, nil, err
	}
	if err = pc.SetMulticastTTL(255); err != nil {
		c.Close()
		return nil, nil, err
	}
	c.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { c.Close() })
	return c, func() { stop(); c.Close() }, nil
}
func localInterface(target netip.Prefix) (*net.Interface, netip.Addr) {
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagMulticast == 0 {
			continue
		}
		as, _ := i.Addrs()
		for _, a := range as {
			p, err := netip.ParsePrefix(a.String())
			if err == nil && p.Addr().Is4() && p.Contains(target.Addr()) {
				return &i, p.Addr()
			}
		}
	}
	return nil, netip.Addr{}
}
func mdnsSweep(ctx context.Context, target netip.Prefix, timeout time.Duration) ([]discoveryHit, error) {
	iface, local := localInterface(target)
	if iface == nil {
		return nil, nil
	}
	c, close, err := multicastSocket(ctx, local, iface, timeout)
	if err != nil {
		return nil, fmt.Errorf("mDNS: %w", err)
	}
	defer close()
	kinds := []string{"_workstation._tcp", "_http._tcp", "_https._tcp", "_ssh._tcp", "_smb._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_hap._tcp", "_home-assistant._tcp", "_spotify-connect._tcp", "_device-info._tcp"}
	// Legacy unicast queries from an ephemeral port avoid taking over the OS mDNS socket.
	for _, kind := range kinds {
		name, _ := dnsmessage.NewName(kind + ".local.")
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x4c41}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}}
		b, _ := m.Pack()
		if _, err = c.WriteToUDP(b, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}); err != nil {
			return nil, fmt.Errorf("mDNS query: %w", err)
		}
	}
	r := newMDNSRecords()
	b := make([]byte, 9000)
	for packets := 0; packets < 512; packets++ {
		n, peer, err := c.ReadFromUDP(b)
		if err != nil {
			break
		}
		if peer.Port != 5353 {
			continue
		}
		peerIP, ok := netip.AddrFromSlice(peer.IP)
		if !ok || !target.Contains(peerIP.Unmap()) {
			continue
		}
		r.ingest(b[:n])
	}
	return r.hits(target), nil
}
func parseSSDP(b []byte) (Advertisement, bool) {
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "HTTP/1.1 200") {
		return Advertisement{}, false
	}
	props := map[string]string{}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		switch k {
		case "server", "location", "st", "usn":
			props[k] = CleanText(strings.TrimSpace(v))
		}
	}
	if len(props) == 0 {
		return Advertisement{}, false
	}
	return Advertisement{Protocol: "ssdp", Service: props["st"], Properties: props}, true
}
func ssdpSweep(ctx context.Context, target netip.Prefix, timeout time.Duration) ([]discoveryHit, error) {
	iface, local := localInterface(target)
	if iface == nil {
		return nil, nil
	}
	c, close, err := multicastSocket(ctx, local, iface, timeout)
	if err != nil {
		return nil, fmt.Errorf("SSDP: %w", err)
	}
	defer close()
	query := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
	if _, err = c.WriteToUDP([]byte(query), &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}); err != nil {
		return nil, fmt.Errorf("SSDP query: %w", err)
	}
	var hits []discoveryHit
	b := make([]byte, 8192)
	for packets := 0; packets < 512; packets++ {
		n, peer, err := c.ReadFromUDP(b)
		if err != nil {
			break
		}
		a, ok := netip.AddrFromSlice(peer.IP)
		if !ok || !target.Contains(a.Unmap()) {
			continue
		}
		ad, ok := parseSSDP(b[:n])
		if ok {
			hits = append(hits, discoveryHit{IP: a.Unmap(), Ads: []Advertisement{ad}, Evidence: "ssdp"})
		}
	}
	return hits, nil
}
