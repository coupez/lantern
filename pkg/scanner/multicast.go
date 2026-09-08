package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"net"
	"net/netip"
	"sort"
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
	pointers  map[string][]string
	display   map[string]string
}

func newMDNSRecords() *mdnsRecords {
	return &mdnsRecords{addresses: map[string][]netip.Addr{}, services: map[string]dnsmessage.SRVResource{}, txt: map[string]map[string]string{}, pointers: map[string][]string{}, display: map[string]string{}}
}
func (r *mdnsRecords) ingest(b []byte) bool {
	var m dnsmessage.Message
	if m.Unpack(b) != nil || !m.Header.Response {
		return false
	}
	records := append(m.Answers, m.Additionals...)
	for _, rr := range records {
		if rr.Header.TTL == 0 || rr.Header.Class&0x7fff != dnsmessage.ClassINET {
			continue
		}
		name := strings.ToLower(rr.Header.Name.String())
		if !strings.HasSuffix(name, ".local.") {
			continue
		}
		if _, ok := r.display[name]; !ok && len(r.display) >= 2048 {
			continue
		}
		r.display[name] = rr.Header.Name.String()
		switch v := rr.Body.(type) {
		case *dnsmessage.PTRResource:
			ptr := strings.ToLower(v.PTR.String())
			if strings.HasSuffix(ptr, ".local.") && !contains(r.pointers[name], ptr) && len(r.pointers[name]) < 128 {
				r.pointers[name] = append(r.pointers[name], ptr)
			}
		case *dnsmessage.AResource:
			a := netip.AddrFrom4(v.A)
			exists := false
			for _, old := range r.addresses[name] {
				if old == a {
					exists = true
				}
			}
			if !exists && len(r.addresses[name]) < 16 {
				r.addresses[name] = append(r.addresses[name], a)
			}
		case *dnsmessage.SRVResource:
			r.services[name] = *v
		case *dnsmessage.TXTResource:
			props := map[string]string{}
			for _, s := range v.TXT {
				key, value, _ := strings.Cut(s, "=")
				key = strings.ToLower(CleanText(key))
				if _, exists := props[key]; !exists {
					props[key] = CleanText(value)
				}
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
			h := discoveryHit{IP: ip, Names: []string{strings.TrimSuffix(r.display[name], ".")}, Evidence: "mdns"}
			for instance, srv := range r.services {
				if !strings.EqualFold(srv.Target.String(), name) {
					continue
				}
				kind := strings.TrimSuffix(serviceType(instance), ".local.")
				h.Ads = append(h.Ads, Advertisement{Protocol: "mdns", Instance: strings.TrimSuffix(r.display[instance], "."), Service: kind, Port: srv.Port, Properties: r.txt[instance]})
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
	return collectMDNS(ctx, c, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}, target)
}

var mdnsKinds = []string{"_services._dns-sd._udp", "_workstation._tcp", "_http._tcp", "_https._tcp", "_ssh._tcp", "_smb._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_hap._tcp", "_home-assistant._tcp", "_spotify-connect._tcp", "_device-info._tcp"}

// serviceType extracts the final service/protocol/domain labels, independently
// of dots or service-looking text in a human-readable instance name.
func serviceType(name string) string {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	n := len(parts)
	if n < 3 || parts[n-1] != "local" || (parts[n-2] != "_tcp" && parts[n-2] != "_udp") || !strings.HasPrefix(parts[n-3], "_") {
		return ""
	}
	return strings.Join(parts[n-3:], ".") + "."
}
func (r *mdnsRecords) followups() []dnsmessage.Question {
	var out []dnsmessage.Question
	add := func(raw string, t dnsmessage.Type) {
		if !strings.HasSuffix(raw, ".local.") {
			return
		}
		n, err := dnsmessage.NewName(raw)
		if err == nil {
			out = append(out, dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET})
		}
	}
	for owner, ptrs := range r.pointers {
		for _, ptr := range ptrs {
			if owner == "_services._dns-sd._udp.local." {
				if serviceType(ptr) == ptr {
					add(ptr, dnsmessage.TypePTR)
				}
				continue
			}
			if serviceType(owner) != owner || !strings.HasSuffix(ptr, "."+owner) {
				continue
			}
			if _, ok := r.services[ptr]; !ok {
				add(ptr, dnsmessage.TypeSRV)
			}
			if _, ok := r.txt[ptr]; !ok {
				add(ptr, dnsmessage.TypeTXT)
			}
		}
	}
	for instance, srv := range r.services {
		if serviceType(instance) == "" {
			continue
		}
		host := strings.ToLower(srv.Target.String())
		if len(r.addresses[host]) == 0 {
			add(host, dnsmessage.TypeA)
		}
		if _, ok := r.txt[instance]; !ok {
			add(instance, dnsmessage.TypeTXT)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name.String() == out[j].Name.String() {
			return out[i].Type < out[j].Type
		}
		return out[i].Name.String() < out[j].Name.String()
	})
	return out
}

// collectMDNS stays within the socket's original deadline; answers cannot extend
// scan duration. A 128-query budget prevents unbounded service enumeration.
func collectMDNS(ctx context.Context, c *net.UDPConn, destination *net.UDPAddr, target netip.Prefix) ([]discoveryHit, error) {
	sent := map[dnsmessage.Question]bool{}
	send := func(q dnsmessage.Question) error {
		if sent[q] || len(sent) >= 128 || ctx.Err() != nil {
			return nil
		}
		sent[q] = true
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x4c41}, Questions: []dnsmessage.Question{q}}
		b, err := m.Pack()
		if err != nil {
			return err
		}
		_, err = c.WriteToUDP(b, destination)
		return err
	}
	for _, kind := range mdnsKinds {
		name, _ := dnsmessage.NewName(kind + ".local.")
		if err := send(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
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
		if peer.Port != destination.Port {
			continue
		}
		ip, ok := netip.AddrFromSlice(peer.IP)
		if !ok || !target.Contains(ip.Unmap()) {
			continue
		}
		if !r.ingest(b[:n]) {
			continue
		}
		if len(sent) >= 128 {
			continue
		}
		for _, q := range r.followups() {
			if err := send(q); err != nil {
				return r.hits(target), fmt.Errorf("mDNS follow-up: %w", err)
			}
		}
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

func normalizeAdvertisements(d *Device) {
	unique := map[string]Advertisement{}
	for _, a := range d.Advertisements {
		b, _ := json.Marshal(a)
		unique[string(b)] = a
	}
	keys := make([]string, 0, len(unique))
	for k := range unique {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	d.Advertisements = nil
	for _, k := range keys {
		d.Advertisements = append(d.Advertisements, unique[k])
	}
}
