package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

func interfacePrefixes(i net.Interface) []netip.Prefix {
	var out []netip.Prefix
	as, _ := i.Addrs()
	for _, a := range as {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p.Addr().Is6() {
			out = append(out, p)
		}
	}
	return out
}
func ipv6Interface(target netip.Prefix, name string) (*net.Interface, []netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var selected *net.Interface
	var prefixes []netip.Prefix
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || (name != "" && name != i.Name) {
			continue
		}
		ps := interfacePrefixes(i)
		matches := false
		for _, p := range ps {
			if target.Overlaps(p) {
				matches = true
			}
		}
		if len(ps) == 0 || (!matches && name == "") {
			continue
		}
		if selected != nil {
			return nil, nil, fmt.Errorf("multiple IPv6 interfaces match; choose --interface")
		}
		copy := i
		selected = &copy
		prefixes = ps
	}
	if selected == nil {
		return nil, nil, fmt.Errorf("no matching local IPv6 interface; specify --interface or scan a single IPv6 address")
	}
	return selected, prefixes, nil
}
func onIPv6Link(a netip.Addr, iface string, prefixes []netip.Prefix) bool {
	if !a.Is6() || a.Is4In6() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Zone() != "" && a.Zone() != iface {
		return false
	}
	if a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range prefixes {
		if inTarget(p, a) {
			return true
		}
	}
	return false
}

type discoveryWarning struct {
	method string
	err    error
}

type ipv6Seeds struct {
	hosts    []netip.Addr
	hits     []discoveryHit
	macs     map[netip.Addr]string
	warnings []discoveryWarning
	iface    string
}

func discoverIPv6(ctx context.Context, o Options, source func(context.Context) (map[netip.Addr]string, error)) (ipv6Seeds, error) {
	result := ipv6Seeds{macs: map[netip.Addr]string{}}
	iface, prefixes, err := ipv6Interface(o.Target, o.Interface)
	if err != nil {
		return result, err
	}
	result.iface = iface.Name
	if source == nil {
		source = func(ctx context.Context) (map[netip.Addr]string, error) { return neighbors6(ctx, iface.Name) }
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	addHits := func(hits []discoveryHit, method string, err error) {
		mu.Lock()
		defer mu.Unlock()
		result.hits = append(result.hits, hits...)
		if err != nil && ctx.Err() == nil {
			result.warnings = append(result.warnings, discoveryWarning{method, err})
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		table, err := source(ctx)
		mu.Lock()
		result.macs = table
		if err != nil && ctx.Err() == nil {
			result.warnings = append(result.warnings, discoveryWarning{"neighbors", err})
		}
		mu.Unlock()
	}()
	if o.ICMP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := pingAllNodes6(ctx, iface, o.Target, o.Timeout, o.MaxHosts, func(h pingHit) { addHits([]discoveryHit{{IP: h.IP, Evidence: "icmp"}}, "icmp", nil) })
			addHits(nil, "icmp", err)
		}()
	}
	if o.Multicast {
		for _, sweep := range []func(context.Context, netip.Prefix, time.Duration, string) ([]discoveryHit, error){mdnsSweepOn, ssdpSweepOn} {
			wg.Add(1)
			go func(sweep func(context.Context, netip.Prefix, time.Duration, string) ([]discoveryHit, error)) {
				defer wg.Done()
				hits, err := sweep(ctx, o.Target, max(o.Timeout, time.Second), iface.Name)
				addHits(hits, "multicast", err)
			}(sweep)
		}
	}
	wg.Wait()
	return filterIPv6Seeds(result, o, iface.Name, prefixes), nil
}

func filterIPv6Seeds(result ipv6Seeds, o Options, iface string, prefixes []netip.Prefix) ipv6Seeds {
	candidates := map[netip.Addr]bool{}
	accept := func(ip netip.Addr) bool { return inTarget(o.Target, ip) && onIPv6Link(ip, iface, prefixes) }
	macs := map[netip.Addr]string{}
	for ip, mac := range result.macs {
		if accept(ip) {
			candidates[scoped(ip, iface)] = true
			macs[scoped(ip, iface)] = mac
		}
	}
	result.macs = macs
	for _, h := range result.hits {
		if accept(h.IP) {
			candidates[scoped(h.IP, iface)] = true
		}
	}
	for _, p := range prefixes {
		ip := scoped(p.Addr(), iface)
		if accept(ip) {
			candidates[ip] = true
			result.hits = append(result.hits, discoveryHit{IP: ip, Evidence: "local-interface"})
		}
	}
	for ip := range candidates {
		result.hosts = append(result.hosts, ip)
	}
	sort.Slice(result.hosts, func(i, j int) bool { return result.hosts[i].Less(result.hosts[j]) })
	if len(result.hosts) > o.MaxHosts {
		result.warnings = append(result.warnings, discoveryWarning{"candidates", fmt.Errorf("IPv6 candidate limit reached: retaining %d of %d discovered addresses", o.MaxHosts, len(result.hosts))})
		result.hosts = result.hosts[:o.MaxHosts]
	}
	keep := map[netip.Addr]bool{}
	for _, ip := range result.hosts {
		keep[ip] = true
	}
	hits := []discoveryHit{}
	for _, h := range result.hits {
		h.IP = scoped(h.IP, iface)
		if keep[h.IP] {
			hits = append(hits, h)
		}
	}
	result.hits = hits
	return result
}
