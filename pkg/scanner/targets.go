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

func Networks() ([]Network, error) {
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
			if err != nil || !p.Addr().Is4() {
				continue
			}
			out = append(out, Network{i.Name, p.Addr().String(), p.Masked().String(), i.HardwareAddr.String()})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.HasPrefix(out[i].Interface, "en") && !strings.HasPrefix(out[j].Interface, "en")
	})
	return out, nil
}
func AutoTarget(iface string) (netip.Prefix, error) {
	networks, err := Networks()
	if err != nil {
		return netip.Prefix{}, err
	}
	if iface == "" {
		if preferred := defaultInterface(); preferred != "" {
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
func ParseTarget(s string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return netip.PrefixFrom(a, 32), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("expected IPv4 address or CIDR, got %q", s)
	}
	return p.Masked(), nil
}
func Hosts(p netip.Prefix, max int) ([]netip.Addr, error) {
	if !p.IsValid() || !p.Addr().Is4() {
		return nil, fmt.Errorf("IPv4 target required")
	}
	count := uint64(1) << uint(32-p.Bits())
	if p.Bits() < 31 {
		count -= 2
	}
	if max < 1 || max > 65536 {
		return nil, fmt.Errorf("max-hosts must be between 1 and 65536")
	}
	if count > uint64(max) {
		return nil, fmt.Errorf("target has %d hosts; limit is %d (use --max-hosts deliberately)", count, max)
	}
	out := make([]netip.Addr, 0, int(count))
	a := p.Masked().Addr()
	if p.Bits() < 31 {
		a = a.Next()
	}
	for range count {
		out = append(out, a)
		a = a.Next()
	}
	return out, nil
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

func defaultInterface() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default")
	case "linux":
		command = exec.CommandContext(ctx, "ip", "-4", "route", "show", "default")
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
