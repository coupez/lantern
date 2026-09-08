package scanner

import (
	"context"
	"fmt"
	"lantern/pkg/vendors"
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
	hosts, err := Hosts(o.Target, o.MaxHosts)
	if err != nil {
		return r, err
	}
	r.Targets = len(hosts)
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
	} // Called under mu: callbacks are serialized.
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
		if fresh {
			snapshot := *d
			snapshot.Evidence = append([]string{}, d.Evidence...)
			snapshot.Ports = append([]Port{}, d.Ports...)
			event(Event{Type: "device", Device: &snapshot})
		}
	}
	requestedPorts := make(map[uint16]bool, len(o.Ports))
	for _, p := range o.Ports {
		if p == 0 {
			return r, fmt.Errorf("port must be between 1 and 65535")
		}
		requestedPorts[p] = true
	}
	var discoveryWG sync.WaitGroup
	var discovered []discoveryHit
	if o.Multicast {
		for _, sweep := range []func(context.Context, netip.Prefix, time.Duration) ([]discoveryHit, error){mdnsSweep, ssdpSweep} {
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
	var pingWG sync.WaitGroup
	if o.ICMP {
		pingWG.Add(1)
		go func() {
			defer pingWG.Done()
			warn(pingSweep(ctx, hosts, o.Timeout, func(h pingHit) { add(h.IP, "icmp", h.RTT, 0) }, markAttempt))
		}()
	}
	type job struct {
		ip   netip.Addr
		port uint16
	}

	run := func(addresses []netip.Addr, ports []uint16) {
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
						event(Event{Type: "progress", Completed: completed, Total: total})
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
	run(hosts, discovery)
	pingWG.Wait()
	discoveryWG.Wait()
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
		source = neighbors
	}
	table, err := source(ctx)
	if ctx.Err() == nil {
		warn(err)
	}
	for _, ip := range hosts {
		if mac, ok := table[ip]; ok {
			add(ip, "neighbor-cache", 0, 0)
			d := found[ip]
			d.MAC = mac
			d.Vendor, _ = vendors.Lookup(mac)
		}
	}
	// The scanning machine may not have an entry in its own ARP table.
	networks, _ := Networks()
	for _, network := range networks {
		ip, err := netip.ParseAddr(network.Address)
		if err != nil || !o.Target.Contains(ip) {
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
		if found[ip] != nil || o.Target.Bits() == 32 || o.AllHosts {
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
	run(scanHosts, scanPorts)
	// Enrichment is bounded independently; slow DNS cannot hold sockets open.
	enrich := make(chan *Device)
	var wg sync.WaitGroup
	for i := 0; i < min(32, len(found)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range enrich {
				if o.Resolve && ctx.Err() == nil {
					c, cancel := context.WithTimeout(ctx, o.Timeout)
					names, err := net.DefaultResolver.LookupAddr(c, d.IP.String())
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
					for i := range d.Ports {
						d.Ports[i].Banner = readBanner(ctx, d.IP, d.Ports[i], o.Timeout)
					}
				}
				sort.Strings(d.Names)
				d.Kind = inferKind(*d)
				sort.Slice(d.Ports, func(i, j int) bool { return d.Ports[i].Number < d.Ports[j].Number })
				sort.Strings(d.Evidence)
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
		return r, fmt.Errorf("all TCP probes failed; check network permissions (first errors: %v)", r.Warnings)
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

// inferKind returns a stable hint derived from advertised or reachable services.
func inferKind(d Device) string {
	services := ""
	for _, a := range d.Advertisements {
		services += " " + strings.ToLower(a.Service)
	}
	for _, rule := range []struct{ needle, kind string }{{"_ipp", "printer"}, {"_printer", "printer"}, {"internetgatewaydevice", "router"}, {"_home-assistant", "smart home hub"}, {"_hap.", "smart home device"}, {"_googlecast", "media"}, {"_airplay", "media"}, {"_raop", "media"}, {"mediarenderer", "media"}} {
		if strings.Contains(services, rule.needle) {
			return rule.kind
		}
	}
	has := func(port uint16) bool {
		for _, p := range d.Ports {
			if p.Number == port {
				return true
			}
		}
		return false
	}
	if has(631) || has(9100) {
		return "printer"
	}
	if has(8008) || has(8009) || has(7000) {
		return "media"
	}
	if has(554) {
		return "camera / media"
	}
	if has(445) || has(3389) {
		return "computer / NAS"
	}
	return "device"
}
