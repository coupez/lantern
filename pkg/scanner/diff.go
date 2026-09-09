package scanner

import (
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Change describes differences in observations, not proof of a physical device
// joining, leaving, changing ownership, or closing a service. Scan-level changes
// have Type "scan" and an empty IP. Before/After are sets; omitted means empty.
type Change struct {
	Type string `json:"type"`
	// Port is set only for service-level catalog changes.
	Port   uint16   `json:"port,omitempty"`
	IP     string   `json:"ip"`
	Detail string   `json:"detail,omitempty"`
	Field  string   `json:"field,omitempty"`
	Before []string `json:"before,omitempty"`
	After  []string `json:"after,omitempty"`
}

func coverageFor(o Options) *ScanCoverage {
	ports := slices.Clone(o.Ports)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	if ports == nil {
		ports = []uint16{}
	}
	return &ScanCoverage{TCPPorts: ports, ICMP: o.ICMP, ARP: o.ARP, NDP: o.NDP, Multicast: o.Multicast, Ubiquiti: o.Ubiquiti, NetBIOS: o.NetBIOS, ReverseDNS: o.Resolve, Descriptions: o.Descriptions, Banners: o.Banners, AllHosts: o.AllHosts}
}
func coverageKey(c *ScanCoverage) []string {
	if c == nil {
		return nil
	}
	out := []string{"tcp=" + portRanges(c.TCPPorts)}
	for _, flag := range []struct {
		name    string
		enabled bool
	}{{"icmp", c.ICMP}, {"arp", c.ARP}, {"ndp", c.NDP}, {"multicast", c.Multicast}, {"ubiquiti", c.Ubiquiti}, {"netbios", c.NetBIOS}, {"reverse-dns", c.ReverseDNS}, {"descriptions", c.Descriptions}, {"banners", c.Banners}, {"all-hosts", c.AllHosts}} {
		out = append(out, flag.name+"="+strconv.FormatBool(flag.enabled))
	}
	return out
}
func sameDiscovery(a, b *ScanCoverage) bool {
	return a == nil || b == nil || (a.ICMP == b.ICMP && a.ARP == b.ARP && a.NDP == b.NDP && a.Multicast == b.Multicast && a.Ubiquiti == b.Ubiquiti && a.NetBIOS == b.NetBIOS && a.AllHosts == b.AllHosts && (len(a.TCPPorts) > 0) == (len(b.TCPPorts) > 0))
}
func sameNames(a, b *ScanCoverage) bool {
	return a == nil || b == nil || (a.Multicast == b.Multicast && a.Ubiquiti == b.Ubiquiti && a.NetBIOS == b.NetBIOS && a.ReverseDNS == b.ReverseDNS)
}
func sameIdentity(a, b *ScanCoverage) bool {
	return a == nil || b == nil || (a.Multicast == b.Multicast && a.Ubiquiti == b.Ubiquiti && a.NetBIOS == b.NetBIOS && a.Descriptions == b.Descriptions)
}

// Diff compares sets of observed values in stable numeric address order. Known
// scan configuration changes are reported separately. Ports are compared only
// where both scans requested them. A cancelled after-scan adds newly observed
// addresses but cannot establish changes or disappearance of existing records.
// Reported discovery failures in the after-scan suppress missing addresses and
// comparisons of fields that depend on those methods. Newly observed values in
// a later complete scan remain reportable, including recovery from partial data.
func Diff(before, after Report) []Change {
	out := []Change{}
	add := func(kind, ip, field, label string, a, b []string) {
		if slices.Equal(a, b) {
			return
		}
		if len(a) == 0 {
			a = nil
		}
		if len(b) == 0 {
			b = nil
		}
		out = append(out, Change{Type: kind, IP: ip, Field: field, Before: slices.Clone(a), After: slices.Clone(b), Detail: label + ": " + displayValues(a) + " → " + displayValues(b)})
	}
	scopeChanged, interfaceChanged := false, false
	if before.Target != "" && after.Target != "" && targetKey(before.Target) != targetKey(after.Target) {
		scopeChanged = true
		add("scan", "", "target", "scan target", []string{before.Target}, []string{after.Target})
	}
	if before.Interface != "" && after.Interface != "" && before.Interface != after.Interface {
		scopeChanged = true
		interfaceChanged = true
		add("scan", "", "interface", "scan interface", []string{before.Interface}, []string{after.Interface})
	}
	a, b := before.Coverage, after.Coverage
	common, samePorts := commonPorts(a, b)
	if (a == nil) != (b == nil) {
		left, right := coverageKey(a), coverageKey(b)
		if a == nil {
			left = []string{"unknown (legacy snapshot)"}
		}
		if b == nil {
			right = []string{"unknown (legacy snapshot)"}
		}
		add("scan", "", "coverage", "requested coverage", left, right)
	}
	if a != nil && b != nil && (!samePorts || coverageFlags(a) != coverageFlags(b)) {
		add("scan", "", "coverage", "requested coverage", coverageKey(a), coverageKey(b))
	}
	add("scan", "", "incomplete_methods", "incomplete discovery methods", stringSet(before.IncompleteMethods), stringSet(after.IncompleteMethods))
	complete := comparisonsAfter(after.IncompleteMethods)
	namesComparable, identityComparable := sameNames(a, b) && complete.names, sameIdentity(a, b) && complete.identity
	kindComparable := identityComparable && samePorts && complete.ports
	old, now := make(map[netip.Addr]*Device, len(before.Devices)), make(map[netip.Addr]*Device, len(after.Devices))
	for i := range before.Devices {
		d := &before.Devices[i]
		old[d.IP] = d
	}
	for i := range after.Devices {
		d := &after.Devices[i]
		now[d.IP] = d
	}
	presenceComparable := !scopeChanged && sameDiscovery(a, b)
	for ip, d := range now {
		address := ip.String()
		previous, ok := old[ip]
		if !ok {
			if presenceComparable {
				out = append(out, Change{Type: "added", IP: address, Detail: CleanText(d.MAC)})
			}
			continue
		}
		if after.Cancelled || after.Error != "" || interfaceChanged {
			continue
		}
		if presenceComparable && complete.presence {
			add("changed", address, "reachability", "response evidence", one(responseLabel(previous)), one(responseLabel(d)))
		}
		if complete.mac {
			add("changed", address, "mac", "MAC observed", one(macKey(previous.MAC)), one(macKey(d.MAC)))
			add("changed", address, "vendor", "registered vendor", one(previous.Vendor.Name), one(d.Vendor.Name))
		}
		if complete.workgroups && (a == nil || b == nil || a.NetBIOS == b.NetBIOS) {
			add("changed", address, "workgroups", "workgroups observed", workgroups(previous), workgroups(d))
		}
		if complete.ports {
			portsBefore, portsAfter := comparablePorts(previous, d, common)
			add("changed", address, "ports", "TCP ports observed", portsBefore, portsAfter)
		}
		if complete.ports && a != nil && b != nil && a.Banners && b.Banners && !before.Cancelled && before.Error == "" {
			out = appendServiceChanges(out, address, previous, d, common)
		}
		if namesComparable {
			add("changed", address, "names", "names observed", nameValues(previous.Names), nameValues(d.Names))
		}
		if identityComparable {
			oldID, newID := previous.Identity, d.Identity
			if oldID == nil {
				oldID = &Identity{}
			}
			if newID == nil {
				newID = &Identity{}
			}
			add("changed", address, "identity.name", "reported name", one(oldID.Name), one(newID.Name))
			add("changed", address, "identity.manufacturer", "reported manufacturer", one(oldID.Manufacturer), one(newID.Manufacturer))
			add("changed", address, "identity.firmware", "reported firmware", one(oldID.Firmware), one(newID.Firmware))
			add("changed", address, "identity.firmware_version", "reported firmware version", one(oldID.FirmwareVersion), one(newID.FirmwareVersion))
			add("changed", address, "identity.model", "reported model", one(oldID.Model), one(newID.Model))
			add("changed", address, "identity.model_names", "catalog candidates", stringSet(oldID.ModelNames), stringSet(newID.ModelNames))
		}
		// Type hints depend on both advertised services and requested TCP ports.
		if kindComparable {
			add("changed", address, "kind", "type hint", one(previous.Kind), one(d.Kind))
		}
	}
	if !after.Cancelled && after.Error == "" && presenceComparable && complete.presence {
		for ip, d := range old {
			if _, ok := now[ip]; !ok {
				out = append(out, Change{Type: "missing", IP: ip.String(), Detail: CleanText(d.MAC)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.IP != y.IP {
			xi, xe := netip.ParseAddr(x.IP)
			yi, ye := netip.ParseAddr(y.IP)
			if xe == nil && ye == nil {
				return xi.Compare(yi) < 0
			}
			return x.IP < y.IP
		}
		if x.Port != y.Port {
			return x.Port < y.Port
		}
		if x.Field != y.Field {
			return x.Field < y.Field
		}
		if x.Type != y.Type {
			return x.Type < y.Type
		}
		return x.Detail < y.Detail
	})
	return out
}

type fieldComparisons struct {
	presence, mac, ports, names, identity, workgroups bool
}

func comparisonsAfter(methods []string) fieldComparisons {
	c := fieldComparisons{true, true, true, true, true, true}
	for _, method := range methods {
		if method == "" {
			continue
		}
		if method == "local-model" {
			// Kernel inventory failure cannot make network presence, names or
			// service observations incomplete. Avoid spurious model/type loss.
			c.identity = false
			continue
		}
		c.presence = false
		switch method {
		case "tcp":
			c.ports = false
		case "arp", "ndp", "neighbors":
			c.mac = false
		case "multicast", "ubiquiti":
			c.names, c.identity = false, false
		case "netbios":
			c.names, c.identity, c.workgroups = false, false, false
		case "icmp", "candidates":
			// Retained devices still receive their independent field probes.
		default:
			// A newer producer can add a method whose dependencies we do not
			// know. Preserve additions but avoid misleading field comparisons.
			return fieldComparisons{}
		}
	}
	return c
}

func targetKey(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String()
	}
	return s
}
func macKey(s string) string {
	if mac, err := net.ParseMAC(s); err == nil {
		return mac.String()
	}
	return s
}
func one(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
func stringSet(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
func nameValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.ToLower(strings.TrimSuffix(v, ".")))
	}
	return stringSet(out)
}
func portValues(ports []uint16) []string {
	// The comparison normalizes numbers before converting changed sets to text.
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, strconv.Itoa(int(p)))
	}
	return out
}

// Fixed-size bitsets bound comparison work independently of device count.
type portSet [1024]uint64

func commonPorts(a, b *ScanCoverage) (*portSet, bool) {
	if a == nil || b == nil {
		return nil, true
	}
	var first, second portSet
	for _, p := range a.TCPPorts {
		first[p/64] |= uint64(1) << (p % 64)
	}
	for _, p := range b.TCPPorts {
		second[p/64] |= uint64(1) << (p % 64)
	}
	same := first == second
	for i := range first {
		first[i] &= second[i]
	}
	return &first, same
}
func coverageFlags(c *ScanCoverage) [10]bool {
	return [10]bool{c.ICMP, c.ARP, c.NDP, c.Multicast, c.Ubiquiti, c.NetBIOS, c.ReverseDNS, c.Descriptions, c.Banners, c.AllHosts}
}
func comparablePorts(old, now *Device, common *portSet) ([]string, []string) {
	// Completed scans normally retain the same ordered port observations. Avoid
	// copying, sorting, and formatting those lists on every watch refresh. Service
	// labels/banners are deliberately outside this port-number comparison.
	if len(old.Ports) == len(now.Ports) {
		same := true
		for i, p := range old.Ports {
			if p.Number != now.Ports[i].Number {
				same = false
				break
			}
		}
		if same {
			return nil, nil
		}
	}
	values := func(d *Device) []uint16 {
		ports := make([]uint16, 0, len(d.Ports))
		for _, p := range d.Ports {
			if common == nil || common[p.Number/64]&(uint64(1)<<(p.Number%64)) != 0 {
				ports = append(ports, p.Number)
			}
		}
		slices.Sort(ports)
		return slices.Compact(ports)
	}
	a, b := values(old), values(now)
	if slices.Equal(a, b) {
		return nil, nil
	}
	return portValues(a), portValues(b)
}
func displayValues(values []string) string {
	if len(values) == 0 {
		return "(not observed)"
	}
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = strconv.Quote(v)
	}
	return strings.Join(quoted, ", ")
}

func workgroups(d *Device) []string {
	var values []string
	for _, ad := range d.Advertisements {
		if ad.Protocol == "netbios" && ad.Service == "workgroup" {
			values = append(values, strings.ToLower(ad.Properties["name"]))
		}
	}
	return stringSet(values)
}

func responseLabel(d *Device) string {
	if d.Responsive() {
		return "responsive"
	}
	if contains(d.Evidence, "neighbor-cache") {
		return "cached only"
	}
	return "unconfirmed"
}

func portRanges(ports []uint16) string {
	sorted := slices.Clone(ports)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) == 0 {
		return "none"
	}
	var ranges []string
	for i := 0; i < len(sorted); i++ {
		start := sorted[i]
		for i+1 < len(sorted) && int(sorted[i+1]) == int(sorted[i])+1 {
			i++
		}
		label := strconv.Itoa(int(start))
		if sorted[i] != start {
			label += "-" + strconv.Itoa(int(sorted[i]))
		}
		ranges = append(ranges, label)
	}
	return strings.Join(ranges, ",")
}
