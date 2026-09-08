package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Network struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	CIDR      string `json:"cidr"`
	MAC       string `json:"mac,omitempty"`
}

func Networks() ([]Network, error)  { return networksFor(false) }
func Networks6() ([]Network, error) { return networksFor(true) }
func networksFor(v6 bool) ([]Network, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Network
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || p.Addr().Is6() != v6 {
				continue
			}
			out = append(out, Network{i.Name, scoped(p.Addr(), i.Name).String(), p.Masked().String(), i.HardwareAddr.String()})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.HasPrefix(out[i].Interface, "en") && !strings.HasPrefix(out[j].Interface, "en")
	})
	return out, nil
}
func AutoTarget(iface string) (netip.Prefix, error) {
	return autoTargetContext(context.Background(), iface)
}
func autoTargetContext(ctx context.Context, iface string) (netip.Prefix, error) {
	networks, err := Networks()
	if err != nil {
		return netip.Prefix{}, err
	}
	if iface == "" {
		if preferred := defaultInterfaceContext(ctx, false); preferred != "" {
			for _, n := range networks {
				if n.Interface == preferred {
					return netip.ParsePrefix(n.CIDR)
				}
			}
		}
	}
	var matches []Network
	for _, n := range networks {
		if iface == "" || n.Interface == iface {
			matches = append(matches, n)
		}
	}
	if len(matches) == 0 {
		return netip.Prefix{}, fmt.Errorf("no IPv4 network found; specify an IP or CIDR")
	}
	if len(matches) > 1 && iface == "" {
		return netip.Prefix{}, fmt.Errorf("multiple networks found; choose --interface or a CIDR (see lantern interfaces)")
	}
	return netip.ParsePrefix(matches[0].CIDR)
}

// ParseTarget parses an unscoped address/prefix. Use ParseTargetSpec for zones.
func ParseTarget(s string) (netip.Prefix, error) {
	p, zone, err := ParseTargetSpec(s)
	if err == nil && zone != "" {
		return netip.Prefix{}, fmt.Errorf("scoped target requires ParseTargetSpec and Options.Interface")
	}
	return p, err
}

// ParseTargetSpec preserves an IPv6 zone separately for Options.Interface.
func ParseTargetSpec(s string) (netip.Prefix, string, error) {
	addrPart, bitsPart, hasPrefix := strings.Cut(s, "/")
	a, err := netip.ParseAddr(addrPart)
	if err != nil {
		return netip.Prefix{}, "", fmt.Errorf("expected an IP address or CIDR, got %q", s)
	}
	if a.Is4In6() {
		return netip.Prefix{}, "", fmt.Errorf("use a native IPv4 address instead of an IPv4-mapped IPv6 address")
	}
	zone := a.Zone()
	a = a.WithZone("")
	bits := a.BitLen()
	if hasPrefix {
		bits, err = strconv.Atoi(bitsPart)
		if err != nil || bits < 0 || bits > a.BitLen() {
			return netip.Prefix{}, "", fmt.Errorf("invalid prefix length in %q", s)
		}
	}
	if a.IsMulticast() || (a.IsUnspecified() && bits == a.BitLen()) {
		return netip.Prefix{}, "", fmt.Errorf("target must be a unicast address or a network prefix")
	}
	return netip.PrefixFrom(a, bits).Masked(), zone, nil
}
func Hosts(p netip.Prefix, limit int) ([]netip.Addr, error) {
	if !p.IsValid() || p.Addr().Is4In6() {
		return nil, fmt.Errorf("valid native IPv4 or IPv6 target required")
	}
	if limit < 1 || limit > 65536 {
		return nil, fmt.Errorf("max-hosts must be between 1 and 65536")
	}
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits > 16 {
		return nil, fmt.Errorf("target is too large to enumerate; IPv6 scans use local discovery automatically")
	}
	count := uint64(1) << uint(hostBits)
	if p.Addr().Is4() && p.Bits() < 31 {
		count -= 2
	}
	if count > uint64(limit) {
		return nil, fmt.Errorf("target has %d hosts; limit is %d (use --max-hosts deliberately)", count, limit)
	}
	out := make([]netip.Addr, 0, int(count))
	a := p.Masked().Addr()
	if p.Addr().Is4() && p.Bits() < 31 {
		a = a.Next()
	}
	for range count {
		out = append(out, a)
		a = a.Next()
	}
	return out, nil
}
func sparseIPv6(p netip.Prefix, limit int) bool {
	if !p.IsValid() || !p.Addr().Is6() {
		return false
	}
	bits := 128 - p.Bits()
	return bits > 16 || (uint64(1)<<uint(bits)) > uint64(limit)
}
func scoped(a netip.Addr, iface string) netip.Addr {
	if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" && iface != "" {
		return a.WithZone(iface)
	}
	return a
}
func inTarget(p netip.Prefix, a netip.Addr) bool { return p.Contains(a.WithZone("")) }

// AutoTarget6 selects one interface, then discovers its IPv6 neighbors without
// attempting to enumerate its full address space.
func AutoTarget6(iface string) (netip.Prefix, string, error) {
	return autoTarget6Context(context.Background(), iface)
}
func autoTarget6Context(ctx context.Context, iface string) (netip.Prefix, string, error) {
	if iface == "" {
		iface = defaultInterfaceContext(ctx, true)
		if iface == "" {
			iface = defaultInterfaceContext(ctx, false)
		}
	}
	selected, _, err := ipv6Interface(netip.MustParsePrefix("::/0"), iface)
	if err != nil {
		return netip.Prefix{}, "", err
	}
	return netip.MustParsePrefix("::/0"), selected.Name, nil
}
func ParsePorts(s string) ([]uint16, error) {
	if s == "none" {
		return nil, nil
	}
	seen := map[uint16]bool{}
	var out []uint16
	for _, part := range strings.Split(s, ",") {
		parts := strings.Split(strings.TrimSpace(part), "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		lo, err := strconv.Atoi(parts[0])
		if err != nil || lo < 1 || lo > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		hi := lo
		if len(parts) == 2 {
			hi, err = strconv.Atoi(parts[1])
			if err != nil || hi < lo || hi > 65535 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		for p := lo; p <= hi; p++ {
			if !seen[uint16(p)] {
				out = append(out, uint16(p))
				seen[uint16(p)] = true
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func defaultInterface() string { return defaultInterfaceFor(false) }
func defaultInterfaceFor(v6 bool) string {
	return defaultInterfaceContext(context.Background(), v6)
}
func defaultInterfaceContext(ctx context.Context, v6 bool) string {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		args := []string{"-n", "get", "default"}
		if v6 {
			args = []string{"-n", "get", "-inet6", "default"}
		}
		command = exec.CommandContext(ctx, "/sbin/route", args...)
	case "linux":
		family := "-4"
		if v6 {
			family = "-6"
		}
		command = exec.CommandContext(ctx, "ip", family, "route", "show", "default")
	default:
		return ""
	}
	b, err := command.Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	for i, v := range f {
		if (v == "interface:" || v == "dev") && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}
