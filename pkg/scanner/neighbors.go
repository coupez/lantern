package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var arpLine = regexp.MustCompile(`\(([^)]+)\) at ([0-9a-fA-F:]+)`)

func parseNeighbors(s string) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	for _, line := range strings.Split(s, "\n") {
		var addr, mac string
		if m := arpLine.FindStringSubmatch(line); m != nil {
			addr, mac = m[1], m[2]
		} else {
			f := strings.Fields(line)
			if len(f) > 0 {
				addr = f[0]
			}
			for i, v := range f {
				if v == "lladdr" && i+1 < len(f) {
					mac = f[i+1]
				}
			}
		}
		parts := strings.Split(mac, ":")
		if len(parts) != 6 {
			continue
		}
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		mac = strings.Join(parts, ":")
		ip, e := netip.ParseAddr(addr)
		hw, e2 := net.ParseMAC(mac)
		if e == nil && e2 == nil && ip.Is4() {
			out[ip] = hw.String()
		}
	}
	return out
}
func neighbors(ctx context.Context) (map[netip.Addr]string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/sbin/arp", "-an")
	case "linux":
		cmd = exec.CommandContext(ctx, "ip", "-4", "neigh", "show")
	default:
		return nil, fmt.Errorf("neighbor lookup unsupported on %s", runtime.GOOS)
	}
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("neighbor lookup: %w", err)
	}
	return parseNeighbors(string(b)), nil
}

func parseNeighbors6(s, iface string) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil || !ip.Is6() || ip.Is4In6() {
			continue
		}
		mac, device := "", ""
		if f[1] == "dev" {
			device = f[2]
			for i, v := range f {
				if v == "lladdr" && i+1 < len(f) {
					mac = f[i+1]
				}
			}
		} else {
			mac = f[1]
			device = f[2]
		}
		if iface != "" && device != iface {
			continue
		}
		if ip.Zone() != "" && ip.Zone() != device {
			continue
		}
		parts := strings.Split(mac, ":")
		if len(parts) != 6 {
			continue
		}
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		hw, err := net.ParseMAC(strings.Join(parts, ":"))
		if err != nil || hw[0]&1 != 0 {
			continue
		}
		out[scoped(ip, device)] = hw.String()
	}
	return out
}
func neighbors6(ctx context.Context, iface string) (map[netip.Addr]string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/sbin/ndp", "-an")
	case "linux":
		args := []string{"-6", "neigh", "show"}
		if iface != "" {
			args = append(args, "dev", iface)
		}
		cmd = exec.CommandContext(ctx, "ip", args...)
	default:
		return nil, fmt.Errorf("IPv6 neighbor lookup unsupported on %s", runtime.GOOS)
	}
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("IPv6 neighbor lookup: %w", err)
	}
	return parseNeighbors6(string(b), iface), nil
}
