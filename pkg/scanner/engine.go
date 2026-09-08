package scanner

import (
	"context"
	"fmt"
	"github.com/coupez/lantern/pkg/vendors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	Dialer         Dialer
	NeighborSource func(context.Context) (map[netip.Addr]string, error)
	// NetBIOSSource optionally replaces the UDP node-status exchange.
	NetBIOSSource func(context.Context, []netip.Addr, time.Duration) (NetBIOSResult, error)
	// ARPSource optionally replaces native ARP exchange for integrations/tests.
	ARPSource func(context.Context, Options, []netip.Addr) (ARPResult, error)
	// NDPSource optionally replaces native IPv6 neighbor solicitation.
	NDPSource func(context.Context, Options, []netip.Addr) (NDPResult, error)
}

func (e Engine) Scan(ctx context.Context, o Options, emit func(Event)) (Report, error) {
	start := time.Now()
	r := Report{Schema: 1, Target: o.Target.String(), Started: start.UTC(), Devices: []Device{}}
	if o.Concurrency < 1 || o.Concurrency > 4096 {
		return r, fmt.Errorf("concurrency must be between 1 and 4096")
	}
	if o.Timeout <= 0 || o.Timeout > 30*time.Second {
		return r, fmt.Errorf("timeout must be >0 and <=30s")
	}
	if o.MaxHosts < 1 || o.MaxHosts > 65536 {
		return r, fmt.Errorf("max-hosts must be between 1 and 65536")
	}
	if !o.Target.IsValid() || o.Target.Addr().Is4In6() || o.Target.Addr().IsMulticast() || (o.Target.Addr().IsUnspecified() && o.Target.Bits() == o.Target.Addr().BitLen()) {
		return r, fmt.Errorf("valid native IP target required")
	}
	if o.ARP && !o.Target.Addr().Is4() {
		return r, fmt.Errorf("ARP requires an IPv4 target; IPv6 uses neighbor discovery")
	}
	if o.NDP && !o.Target.Addr().Is6() {
		return r, fmt.Errorf("NDP requires an IPv6 target; IPv4 uses ARP")
	}
	if o.NetBIOS && !o.Target.Addr().Is4() {
		return r, fmt.Errorf("NetBIOS discovery requires an IPv4 target")
	}
	requestedPorts := make(map[uint16]bool, min(len(o.Ports), 65535))
	ports := make([]uint16, 0, min(len(o.Ports), 65535))
	for _, p := range o.Ports {
		if p == 0 {
			return r, fmt.Errorf("port must be between 1 and 65535")
		}
		if !requestedPorts[p] {
			requestedPorts[p] = true
			ports = append(ports, p)
		}
	}
	o.Ports = ports // Own the execution plan; never change the caller's slice.
	if o.NDP && o.Interface == "" && e.NDPSource == nil {
		if link, err := ndpInterface(o.Target, ""); err == nil {
			o.Interface = link.iface.Name
		}
	}
	r.Coverage = coverageFor(o)
	sparse := sparseIPv6(o.Target, o.MaxHosts)
	if o.Target.Addr().Is6() && !sparse && o.Target.Addr().IsLinkLocalUnicast() && o.Interface == "" {
		return r, fmt.Errorf("link-local IPv6 target needs --interface or an %%interface zone")
	}
	if o.Interface != "" {
		if _, err := net.InterfaceByName(o.Interface); err != nil {
			return r, err
		}
	}
	var hosts []netip.Addr
	var seeds ipv6Seeds
	var err error
	if sparse {
		seeds, err = discoverIPv6(ctx, o, e.NeighborSource)
		hosts = seeds.hosts
		o.Interface = seeds.iface
		r.AddressMode = "discovered"
	} else {
		hosts, err = Hosts(o.Target, o.MaxHosts)
		r.AddressMode = "enumerated"
		for i := range hosts {
			hosts[i] = scoped(hosts[i], o.Interface)
		}
	}
	if err != nil {
		return r, err
	}
	r.Interface = o.Interface
	r.Targets = len(hosts)
	targeted := make(map[netip.Addr]bool, len(hosts))
	for _, ip := range hosts {
		targeted[ip] = true
	}
	dialer := e.Dialer
	if dialer == nil {
		dialer = tcpDialer{}
	}
	var mu sync.Mutex
	found := map[netip.Addr]*Device{}
	warnings := map[string]bool{}
	attempted := map[netip.Addr]bool{}
	tcpAttempts, tcpErrors := 0, 0
	markAttempt := func(ip netip.Addr) { mu.Lock(); attempted[ip] = true; mu.Unlock() }
	event := func(v Event) {
		if emit != nil {
			emit(v)
		}
	} // Concurrent producers hold mu; phase/done events follow producer joins.
	warn := func(err error) {
		if err != nil {
			mu.Lock()
			message := err.Error()
			if len(warnings) < 16 {
				warnings[message] = true
			} else {
				warnings["additional probe errors omitted"] = true
			}
			mu.Unlock()
		}
	}
	add := func(ip netip.Addr, evidence string, rtt time.Duration, port uint16) {
		mu.Lock()
		defer mu.Unlock()
		d := found[ip]
		fresh := d == nil
		if fresh {
			d = &Device{IP: ip, Evidence: []string{}}
			found[ip] = d
		}
		if rtt > 0 && (d.LatencyMS == 0 || float64(rtt)/float64(time.Millisecond) < d.LatencyMS) {
			d.LatencyMS = float64(rtt) / float64(time.Millisecond)
		}
		if !contains(d.Evidence, evidence) {
			d.Evidence = append(d.Evidence, evidence)
		}
		if port > 0 {
			exists := false
			for _, p := range d.Ports {
				if p.Number == port {
					exists = true
				}
			}
			if !exists {
				service := serviceName(port)
				if service == "" {
					service = "unknown"
				}
				d.Ports = append(d.Ports, Port{Number: port, Service: service})
			}
		}
		if fresh && emit != nil {
			snapshot := d.Clone()
			event(Event{Type: "device", Device: &snapshot})
		}
	}
	for _, err := range seeds.warnings {
		warn(err)
	}
	if sparse {
		for _, ip := range hosts {
			if mac, ok := seeds.macs[ip]; ok {
				add(ip, "neighbor-cache", 0, 0)
				d := found[ip]
				d.MAC = mac
				d.Vendor, _ = vendors.Lookup(mac)
			}
		}
		for _, h := range seeds.hits {
			add(h.IP, h.Evidence, 0, 0)
			d := found[h.IP]
			for _, name := range h.Names {
				if !contains(d.Names, name) {
					d.Names = append(d.Names, name)
				}
			}
			d.Advertisements = append(d.Advertisements, h.Ads...)
		}
	}
	var discoveryWG sync.WaitGroup
	var discovered []discoveryHit
	if o.Multicast && !sparse {
		for _, sweep := range []func(context.Context, netip.Prefix, time.Duration) ([]discoveryHit, error){
			func(ctx context.Context, p netip.Prefix, t time.Duration) ([]discoveryHit, error) {
				return mdnsSweepOn(ctx, p, t, o.Interface)
			},
			func(ctx context.Context, p netip.Prefix, t time.Duration) ([]discoveryHit, error) {
				return ssdpSweepOn(ctx, p, t, o.Interface)
			},
		} {
			discoveryWG.Add(1)
			go func(sweep func(context.Context, netip.Prefix, time.Duration) ([]discoveryHit, error)) {
				defer discoveryWG.Done()
				hits, err := sweep(ctx, o.Target, max(o.Timeout, time.Second))
				warn(err)
				mu.Lock()
				discovered = append(discovered, hits...)
				mu.Unlock()
			}(sweep)
		}
	}
	var netbiosWG sync.WaitGroup
	var netbiosResult NetBIOSResult
	if o.NetBIOS {
		netbiosWG.Add(1)
		go func() {
			defer netbiosWG.Done()
			source := e.NetBIOSSource
			if source == nil {
				source = netbiosSweep
			}
			var err error
			netbiosResult, err = source(ctx, hosts, o.Timeout)
			if ctx.Err() == nil {
				warn(err)
			}
		}()
	}
	var arpWG sync.WaitGroup
	var arpResult ARPResult
	if o.ARP {
		arpWG.Add(1)
		go func() {
			defer arpWG.Done()
			source := e.ARPSource
			if source == nil {
				source = arpSweep
			}
			var err error
			arpResult, err = source(ctx, o, hosts)
			if ctx.Err() == nil {
				warn(err)
			}
		}()
	}
	var ndpWG sync.WaitGroup
	var ndpResult NDPResult
	if o.NDP {
		ndpWG.Add(1)
		go func() {
			defer ndpWG.Done()
			source := e.NDPSource
			if source == nil {
				source = ndpSweep
			}
			var err error
			ndpResult, err = source(ctx, o, hosts)
			if ctx.Err() == nil {
				warn(err)
			}
		}()
	}
	var pingWG sync.WaitGroup
	if o.ICMP {
		pingWG.Add(1)
		go func() {
			defer pingWG.Done()
			stats, err := pingSweep(ctx, hosts, o.Timeout, func(h pingHit) { add(h.IP, "icmp", h.RTT, 0) }, markAttempt)
			r.ICMP = &stats
			warn(err)
		}()
	}
	type job struct {
		ip   netip.Addr
		port uint16
	}

	run := func(addresses []netip.Addr, ports []uint16, phase string) {
		total := len(addresses) * len(ports)
		lastProgress := time.Time{}
		ch := make(chan job)
		var wg sync.WaitGroup
		completed := 0
		for i := 0; i < min(o.Concurrency, total); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range ch {
					if ctx.Err() != nil {
						continue
					}
					markAttempt(j.ip)
					alive, open, rtt, err := dialer.Probe(ctx, j.ip, j.port, o.Timeout)
					if err != nil {
						warn(err)
					}
					if alive {
						var port uint16
						ev := "tcp-refused"
						if open {
							if requestedPorts[j.port] {
								port = j.port
							}
							ev = "tcp-open"
						}
						add(j.ip, ev, rtt, port)
					}
					mu.Lock()
					tcpAttempts++
					if err != nil {
						tcpErrors++
					}
					completed++
					if completed == total || time.Since(lastProgress) > 100*time.Millisecond {
						lastProgress = time.Now()
						event(Event{Type: "progress", Phase: phase, Completed: completed, Total: total})
					}
					mu.Unlock()
				}
			}()
		}
	send:
		for _, p := range ports {
			for _, ip := range addresses {
				select {
				case ch <- job{ip, p}:
				case <-ctx.Done():
					break send
				}
			}
		}
		close(ch)
		wg.Wait()
	}
	discovery := []uint16{80, 443, 22}
	if len(o.Ports) == 0 {
		discovery = nil
	}
	run(hosts, discovery, "discovery")
	pingWG.Wait()
	discoveryWG.Wait()
	arpWG.Wait()
	ndpWG.Wait()
	netbiosWG.Wait()
	for _, ip := range netbiosResult.Probed {
		if targeted[ip] {
			markAttempt(ip)
		}
	}
	seenNetBIOS := map[netip.Addr]bool{}
	for _, reply := range netbiosResult.Replies {
		if !targeted[reply.IP] || seenNetBIOS[reply.IP] {
			continue
		}
		seenNetBIOS[reply.IP] = true
		discovered = append(discovered, netbiosHit(reply))
	}
	for _, result := range []struct {
		evidence  string
		probed    []netip.Addr
		neighbors []Neighbor
	}{
		{"arp", arpResult.Probed, arpResult.Neighbors}, {"ndp", ndpResult.Probed, ndpResult.Neighbors},
	} {
		for _, ip := range result.probed {
			if targeted[ip] {
				markAttempt(ip)
			}
		}
		for _, n := range result.neighbors {
			if !targeted[n.IP] {
				continue
			}
			mac, err := net.ParseMAC(n.MAC)
			if err != nil || !validEthernetMAC(mac) {
				continue
			}
			add(n.IP, result.evidence, n.RTT, 0)
			d := found[n.IP]
			d.MAC = mac.String()
			d.Vendor, _ = vendors.Lookup(d.MAC)
		}
	}
	for _, h := range discovered {
		add(h.IP, h.Evidence, 0, 0)
		d := found[h.IP]
		for _, n := range h.Names {
			if !contains(d.Names, n) {
				d.Names = append(d.Names, n)
			}
		}
		d.Advertisements = append(d.Advertisements, h.Ads...)
	}
	// Neighbor entries are observations, not proof of current reachability.
	source := e.NeighborSource
	if source == nil {
		if o.Target.Addr().Is6() {
			source = func(ctx context.Context) (map[netip.Addr]string, error) { return neighbors6(ctx, o.Interface) }
		} else {
			source = func(ctx context.Context) (map[netip.Addr]string, error) { return neighborsOn(ctx, o.Interface) }
		}
	}
	table, err := source(ctx)
	if ctx.Err() == nil {
		warn(err)
	}
	for _, ip := range hosts {
		if mac, ok := table[ip]; ok {
			add(ip, "neighbor-cache", 0, 0)
			d := found[ip]
			if !contains(d.Evidence, "arp") && !contains(d.Evidence, "ndp") {
				d.MAC = mac
				d.Vendor, _ = vendors.Lookup(mac)
			}
		}
	}
	// The scanning machine may not have an entry in its own ARP table.
	networks, _ := Networks()
	if o.Target.Addr().Is6() {
		networks, _ = Networks6()
	}
	for _, network := range networks {
		ip, err := netip.ParseAddr(network.Address)
		if err != nil || !targeted[ip] || (o.Interface != "" && network.Interface != o.Interface) {
			continue
		}
		add(ip, "local-interface", 0, 0)
		d := found[ip]
		d.MAC = network.MAC
		if d.MAC != "" {
			d.Vendor, _ = vendors.Lookup(d.MAC)
		}
	}
	var scanHosts []netip.Addr
	for _, ip := range hosts {
		if found[ip] != nil || o.Target.Bits() == o.Target.Addr().BitLen() || o.AllHosts {
			scanHosts = append(scanHosts, ip)
		}
	}
	var scanPorts []uint16
	for _, p := range o.Ports {
		skip := false
		for _, dp := range discovery {
			if p == dp {
				skip = true
			}
		}
		if !skip {
			scanPorts = append(scanPorts, p)
		}
	}
	run(scanHosts, scanPorts, "ports")
	// Enrichment is bounded independently; slow DNS cannot hold sockets open.
	enriched := 0
	event(Event{Type: "progress", Phase: "enrichment", Total: len(found)})
	enrich := make(chan *Device)
	bannerSlots := make(chan struct{}, min(32, o.Concurrency))
	var wg sync.WaitGroup
	for i := 0; i < min(32, len(found)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range enrich {
				if o.Resolve && ctx.Err() == nil {
					c, cancel := context.WithTimeout(ctx, o.Timeout)
					names, err := net.DefaultResolver.LookupAddr(c, d.IP.WithZone("").String())
					cancel()
					if err == nil {
						for _, name := range names {
							clean := strings.TrimSuffix(name, ".")
							if !contains(d.Names, clean) {
								d.Names = append(d.Names, clean)
							}
						}
					}
				}
				if o.Banners && ctx.Err() == nil {
					enrichBanners(ctx, d, o.Timeout, bannerSlots, readBanner)
				}
				if o.Descriptions && ctx.Err() == nil {
					enrichDescriptions(ctx, d, o.Timeout)
				}
				normalizeAdvertisements(d)
				d.Identity = identify(d.Advertisements)
				sort.Strings(d.Names)
				d.Kind = inferKind(*d)
				sort.Slice(d.Ports, func(i, j int) bool { return d.Ports[i].Number < d.Ports[j].Number })
				sort.Strings(d.Evidence)
				if emit != nil {
					snapshot := d.Clone()
					mu.Lock()
					enriched++
					event(Event{Type: "device_update", Phase: "enrichment", Device: &snapshot, Completed: enriched, Total: len(found)})
					mu.Unlock()
				}
			}
		}()
	}
	for _, d := range found {
		enrich <- d
	}
	close(enrich)
	wg.Wait()
	for _, d := range found {
		r.Devices = append(r.Devices, *d)
	}
	sort.Slice(r.Devices, func(i, j int) bool { return r.Devices[i].IP.Less(r.Devices[j].IP) })
	for w := range warnings {
		r.Warnings = append(r.Warnings, w)
	}
	sort.Strings(r.Warnings)
	r.Cancelled = ctx.Err() != nil
	r.DurationMS = time.Since(start).Milliseconds()
	r.Probed = len(attempted)
	event(Event{Type: "done", Completed: r.Probed, Total: len(hosts)})
	if tcpAttempts > 0 && tcpErrors == tcpAttempts && !r.Cancelled {
		err := fmt.Errorf("all TCP probes failed; check network permissions (first errors: %v)", r.Warnings)
		r.Error = err.Error()
		return r, err
	}
	return r, nil
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
