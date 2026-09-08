package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
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
		if _, ok := r.display[name]; !ok {
			r.display[name] = rr.Header.Name.String()
		}
		switch v := rr.Body.(type) {
		case *dnsmessage.PTRResource:
			ptr := strings.ToLower(v.PTR.String())
			if strings.HasSuffix(ptr, ".local.") && !contains(r.pointers[name], ptr) && len(r.pointers[name]) < 128 {
				r.pointers[name] = append(r.pointers[name], ptr)
				// PTR targets carry the advertised instance spelling. Follow-up
				// replies may echo our lowercase query name; keep the original.
				if _, ok := r.display[ptr]; !ok && len(r.display) < 2048 {
					r.display[ptr] = v.PTR.String()
				}
			}
		case *dnsmessage.AAAAResource:
			a := netip.AddrFrom16(v.AAAA)
			if !a.Is4In6() && len(r.addresses[name]) < 16 {
				exists := false
				for _, old := range r.addresses[name] {
					if old == a {
						exists = true
					}
				}
				if !exists {
					r.addresses[name] = append(r.addresses[name], a)
				}
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
				if !validTXTKey(key) {
					continue
				}
				key = strings.ToLower(key)
				if _, exists := props[key]; !exists {
					props[key] = value // Preserve input for recognition; sanitize only display text.
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
			if !target.Contains(ip) || ip.IsUnspecified() || ip.IsMulticast() {
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
	network := "udp4"
	if local.Is6() {
		network = "udp6"
	}
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IP(local.AsSlice()), Zone: local.Zone()})
	if err != nil {
		return nil, nil, err
	}
	if local.Is6() {
		pc := ipv6.NewPacketConn(c)
		err = pc.SetMulticastInterface(iface)
		if err == nil {
			err = pc.SetMulticastHopLimit(255)
		}
	} else {
		pc := ipv4.NewPacketConn(c)
		err = pc.SetMulticastInterface(iface)
		if err == nil {
			err = pc.SetMulticastTTL(255)
		}
	}
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		c.Close()
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	return c, func() { stop(); c.Close() }, nil
}
func localInterface(target netip.Prefix) (*net.Interface, netip.Addr) {
	return localInterfaceOn(target, "")
}
func localInterfaceOn(target netip.Prefix, preferred string) (*net.Interface, netip.Addr) {
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagMulticast == 0 || (preferred != "" && preferred != i.Name) {
			continue
		}
		as, _ := i.Addrs()
		for _, a := range as {
			p, err := netip.ParsePrefix(a.String())
			if err == nil && p.Addr().Is6() == target.Addr().Is6() && target.Overlaps(p) {
				return &i, scoped(p.Addr(), i.Name)
			}
		}
	}
	return nil, netip.Addr{}
}
func mdnsSweep(ctx context.Context, target netip.Prefix, timeout time.Duration) ([]discoveryHit, error) {
	return mdnsSweepOn(ctx, target, timeout, "")
}
func mdnsSweepOn(ctx context.Context, target netip.Prefix, timeout time.Duration, preferred string) ([]discoveryHit, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	iface, local := localInterfaceOn(target, preferred)
	if iface == nil {
		return nil, nil
	}
	c, close, err := multicastSocket(ctx, local, iface, timeout)
	if err != nil {
		return nil, discoveryCompletion(ctx, "mDNS", fmt.Errorf("mDNS socket: %w", err), 0, 0)
	}
	defer close()
	destination := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	if local.Is6() {
		destination = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353, Zone: iface.Name}
	}
	return collectMDNS(ctx, c, destination, target)
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
func (r *mdnsRecords) followups(family6 ...bool) []dnsmessage.Question {
	v6 := len(family6) > 0 && family6[0]
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
		hasAddress := false
		for _, a := range r.addresses[host] {
			if a.Is6() == v6 {
				hasAddress = true
			}
		}
		if !hasAddress {
			typ := dnsmessage.TypeA
			if v6 {
				typ = dnsmessage.TypeAAAA
			}
			add(host, typ)
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
func collectMDNS(ctx context.Context, c discoveryUDPConn, destination *net.UDPAddr, target netip.Prefix) ([]discoveryHit, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	sent := map[dnsmessage.Question]bool{}
	r := newMDNSRecords()
	packets := 0
	finish := func(err error) ([]discoveryHit, error) {
		return scopedHits(r.hits(target), destination.Zone), discoveryCompletion(ctx, "mDNS", err, packets, len(sent))
	}
	send := func(q dnsmessage.Question) error {
		if sent[q] || len(sent) >= maxMDNSQueries || ctx.Err() != nil {
			return nil
		}
		sent[q] = true
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x4c41}, Questions: []dnsmessage.Question{q}}
		b, err := m.Pack()
		if err != nil {
			return err
		}
		return writeDiscoveryDatagram(c, b, destination)
	}
	for _, kind := range mdnsKinds {
		name, _ := dnsmessage.NewName(kind + ".local.")
		if err := send(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
			return finish(fmt.Errorf("mDNS query: %w", err))
		}
	}
	b := make([]byte, 9000)
	for packets < maxDiscoveryPackets && ctx.Err() == nil {
		n, peer, err := c.ReadFromUDP(b)
		if err != nil {
			return finish(discoveryReceiveError("mDNS", err))
		}
		packets++
		if peer.Port != destination.Port || (peer.Zone != "" && peer.Zone != destination.Zone) {
			continue
		}
		ip, ok := netip.AddrFromSlice(peer.IP)
		if !ok || (!inTarget(target, ip.Unmap()) && !(target.Addr().Is6() && ip.IsLinkLocalUnicast() && destination.Zone != "")) {
			continue
		}
		if !r.ingest(b[:n]) {
			continue
		}
		if len(sent) >= maxMDNSQueries {
			continue
		}
		for _, q := range r.followups(target.Addr().Is6()) {
			if err := send(q); err != nil {
				return finish(fmt.Errorf("mDNS follow-up: %w", err))
			}
		}
	}
	return finish(nil)
}

func scopedHits(hits []discoveryHit, zone string) []discoveryHit {
	for i := range hits {
		hits[i].IP = scoped(hits[i].IP, zone)
	}
	return hits
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
	return ssdpSweepOn(ctx, target, timeout, "")
}
func ssdpSweepOn(ctx context.Context, target netip.Prefix, timeout time.Duration, preferred string) ([]discoveryHit, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	iface, local := localInterfaceOn(target, preferred)
	if iface == nil {
		return nil, nil
	}
	c, close, err := multicastSocket(ctx, local, iface, timeout)
	if err != nil {
		return nil, discoveryCompletion(ctx, "SSDP", fmt.Errorf("SSDP socket: %w", err), 0, 0)
	}
	defer close()
	destination := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	if local.Is6() {
		destination = &net.UDPAddr{IP: net.ParseIP("ff02::c"), Port: 1900, Zone: iface.Name}
		err = ipv6.NewPacketConn(c).SetMulticastHopLimit(1)
	} else {
		err = ipv4.NewPacketConn(c).SetMulticastTTL(1)
	}
	if err != nil {
		return nil, discoveryCompletion(ctx, "SSDP", fmt.Errorf("SSDP multicast hop limit: %w", err), 0, 0)
	}
	return collectSSDP(ctx, c, destination, target, iface.Name)
}

func collectSSDP(ctx context.Context, c discoveryUDPConn, destination *net.UDPAddr, target netip.Prefix, zone string) ([]discoveryHit, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	var hits []discoveryHit
	packets := 0
	finish := func(err error) ([]discoveryHit, error) {
		return hits, discoveryCompletion(ctx, "SSDP", err, packets, 0)
	}
	host := net.JoinHostPort(destination.IP.String(), strconv.Itoa(destination.Port))
	query := "M-SEARCH * HTTP/1.1\r\nHOST: " + host + "\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
	if err := writeDiscoveryDatagram(c, []byte(query), destination); err != nil {
		return finish(fmt.Errorf("SSDP query: %w", err))
	}
	b := make([]byte, 8192)
	for packets < maxDiscoveryPackets && ctx.Err() == nil {
		n, peer, err := c.ReadFromUDP(b)
		if err != nil {
			return finish(discoveryReceiveError("SSDP", err))
		}
		packets++
		a, ok := netip.AddrFromSlice(peer.IP)
		if !ok || !inTarget(target, a.Unmap()) || (peer.Zone != "" && peer.Zone != zone) {
			continue
		}
		ad, ok := parseSSDP(b[:n])
		if ok {
			hits = append(hits, discoveryHit{IP: scoped(a.Unmap(), zone), Ads: []Advertisement{ad}, Evidence: "ssdp"})
		}
	}
	return finish(nil)
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

// RFC 6763 section 6.4: printable ASCII, nonempty; '=' is split before this call.
func validTXTKey(key string) bool {
	if key == "" {
		return false
	}
	for i := range len(key) {
		if key[i] < 0x20 || key[i] > 0x7e || key[i] == '=' {
			return false
		}
	}
	return true
}

const (
	maxDiscoveryPackets = 512
	maxMDNSQueries      = 128
)

// Collectors borrow a socket whose owner supplies deadlines and cancellation.
// The minimal interface lets faults be tested without sending network traffic.
type discoveryUDPConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

func writeDiscoveryDatagram(c discoveryUDPConn, packet []byte, destination *net.UDPAddr) error {
	n, err := c.WriteToUDP(packet, destination)
	if err == nil && n != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func discoveryReceiveError(protocol string, err error) error {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return nil
	}
	return fmt.Errorf("%s receive: %w", protocol, err)
}

func discoveryCompletion(ctx context.Context, protocol string, err error, packets, queries int) error {
	if ctx.Err() != nil {
		return nil
	}
	var limits []string
	if queries >= maxMDNSQueries {
		limits = append(limits, fmt.Sprintf("%s query limit reached (%d); some service details may be incomplete", protocol, maxMDNSQueries))
	}
	if packets >= maxDiscoveryPackets {
		limits = append(limits, fmt.Sprintf("%s packet limit reached (%d); discovery may be incomplete", protocol, maxDiscoveryPackets))
	}
	if len(limits) == 0 {
		return err
	}
	message := strings.Join(limits, "; ")
	if err != nil {
		return fmt.Errorf("%w; %s", err, message)
	}
	return errors.New(message)
}
