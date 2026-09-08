package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
)

// DiagnosticCheck describes local access, not remote reachability. Status is
// available, unavailable, or not_checked. An unavailable optional check need not
// prevent a scan from succeeding with other methods.
type DiagnosticCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

type Diagnostics struct {
	Schema     int               `json:"schema"`
	OS         string            `json:"os"`
	Arch       string            `json:"arch"`
	Interface  string            `json:"interface,omitempty"`
	Networks   []Network         `json:"networks"`
	Checks     []DiagnosticCheck `json:"checks"`
	DurationMS int64             `json:"duration_ms"`
	Cancelled  bool              `json:"cancelled,omitempty"`
}

type diagnosticTask struct {
	name, hint string
	check      func(context.Context) (string, error)
}

func runDiagnosticTasks(ctx context.Context, r *Diagnostics, tasks []diagnosticTask) {
	for _, task := range tasks {
		check := DiagnosticCheck{Name: task.name, Hint: task.hint}
		if ctx.Err() != nil {
			check.Status, check.Detail = "not_checked", "cancelled before this check"
		} else {
			detail, err := task.check(ctx)
			switch {
			case ctx.Err() != nil:
				check.Status, check.Detail = "not_checked", "cancelled during this check"
			case err != nil:
				check.Status, check.Detail = "unavailable", err.Error()
			default:
				check.Status, check.Detail, check.Hint = "available", detail, ""
			}
		}
		r.Checks = append(r.Checks, check)
	}
	r.Cancelled = ctx.Err() != nil
}

// checkLocalSocket cannot send or receive through its returned resource. Closing
// errors are surfaced, and every successfully opened resource is closed once.
func checkLocalSocket(open func() (io.Closer, error)) error {
	c, err := open()
	if err != nil {
		return err
	}
	return c.Close()
}

// Diagnose inspects local interfaces, routing/neighbor tables and socket access.
// It opens and closes the scanner's ICMP, multicast and optional ARP/NDP resources;
// it sends no packets, reads no captured frames and changes no permissions.
// Only invalid interface input or cancellation returns an error. Individual
// failures remain in the report so callers can explain partial capabilities.
func Diagnose(ctx context.Context, iface string) (Diagnostics, error) {
	start := time.Now()
	r := Diagnostics{Schema: 1, OS: runtime.GOOS, Arch: runtime.GOARCH, Interface: iface, Networks: []Network{}, Checks: []DiagnosticCheck{}}
	if ctx.Err() != nil {
		r.Cancelled = true
		return r, ctx.Err()
	}
	if iface != "" {
		if _, err := net.InterfaceByName(iface); err != nil {
			return r, fmt.Errorf("interface %q: %w", iface, err)
		}
	}
	var target4, target6 netip.Prefix
	var iface4, iface6 string
	var target4Err, target6Err error
	inventory := func(v6 bool) func(context.Context) (string, error) {
		return func(context.Context) (string, error) {
			networks, err := networksFor(v6)
			if err != nil {
				return "", err
			}
			n := 0
			for _, network := range networks {
				if iface == "" || network.Interface == iface {
					r.Networks = append(r.Networks, network)
					n++
				}
			}
			if n == 0 {
				return "", fmt.Errorf("no active non-loopback networks found")
			}
			return fmt.Sprintf("%d local network addresses", n), nil
		}
	}
	echo := func(network, bind string) func(context.Context) (string, error) {
		return func(context.Context) (string, error) {
			err := checkLocalSocket(func() (io.Closer, error) { return icmp.ListenPacket(network, bind) })
			return "unprivileged ICMP socket opened and closed; no echo sent", err
		}
	}
	multicast := func(v6 bool) func(context.Context) (string, error) {
		return func(ctx context.Context) (string, error) {
			target, preferred, err := target4, iface4, target4Err
			if v6 {
				target, preferred, err = target6, iface6, target6Err
			}
			if err != nil {
				return "", fmt.Errorf("target selection: %w", err)
			}
			_, link, local, closeSocket, err := openMulticastSocket(ctx, target, preferred, time.Second)
			if err != nil {
				return "", err
			}
			if link == nil {
				return "", fmt.Errorf("no multicast-capable interface matches the selected target")
			}
			closeSocket()
			return fmt.Sprintf("multicast socket configured on %s (%s); no query sent", link.Name, local), nil
		}
	}
	tasks := []diagnosticTask{
		{"networks4", "Connect an IPv4 interface or specify a reachable single-host target.", inventory(false)},
		{"networks6", "IPv6 discovery needs an active IPv6 address on the selected interface.", inventory(true)},
		{"target4", "Use lantern interfaces, then select --interface or an explicit IP/CIDR.", func(ctx context.Context) (string, error) {
			target4, iface4, target4Err = autoTarget4Context(ctx, iface)
			if target4Err != nil {
				return "", target4Err
			}
			return target4.String() + " on " + iface4, nil
		}},
		{"target6", "Use lantern interfaces, then select --interface for local IPv6 discovery.", func(ctx context.Context) (string, error) {
			target6, iface6, target6Err = autoTarget6Context(ctx, iface)
			if target6Err != nil {
				return "", target6Err
			}
			return "local IPv6 candidates on " + iface6 + " (the /64 is not enumerated)", nil
		}},
		{"icmp4", "TCP and multicast can still discover devices; Linux ping sockets depend on ping_group_range and the current user/group.", echo("udp4", "0.0.0.0")},
		{"icmp6", "IPv6 TCP and multicast can still work when ICMPv6 socket access is denied.", echo("udp6", "::")},
		{"multicast4", "Check the selected interface and local network permissions; --no-multicast skips this discovery method.", multicast(false)},
		{"multicast6", "Select an IPv6 interface and check local network permissions; --no-multicast skips this method.", multicast(true)},
		{"arp", "ARP is optional (--arp); raw access needs BPF access on macOS or CAP_NET_RAW on Linux. Other discovery methods may still work.", func(context.Context) (string, error) {
			if target4Err != nil {
				return "", fmt.Errorf("target selection: %w", target4Err)
			}
			link, err := arpInterface(target4, iface4)
			if err != nil {
				return "", err
			}
			err = checkLocalSocket(func() (io.Closer, error) { return openARP(&link.iface) })
			return "raw ARP resource opened and closed on " + link.iface.Name + "; no frame read or sent", err
		}},
		{"ndp", "NDP is optional (--ndp); use an IPv6 Ethernet interface with BPF access on macOS or CAP_NET_RAW on Linux.", func(context.Context) (string, error) {
			if target6Err != nil {
				return "", fmt.Errorf("target selection: %w", target6Err)
			}
			link, err := ndpInterface(target6, iface6)
			if err != nil {
				return "", err
			}
			err = checkLocalSocket(func() (io.Closer, error) { return openNDP(&link.iface) })
			return "raw NDP resource opened and closed on " + link.iface.Name + "; no frame read or sent", err
		}},
		{"neighbors4", "The OS neighbor table is optional evidence; Linux needs the ip command and macOS uses /usr/sbin/arp.", func(ctx context.Context) (string, error) {
			entries, err := neighborsOn(ctx, iface)
			return fmt.Sprintf("IPv4 neighbor table readable (%d mappings; entries may be stale)", len(entries)), err
		}},
		{"neighbors6", "The IPv6 neighbor table uses ip on Linux and /usr/sbin/ndp on macOS.", func(ctx context.Context) (string, error) {
			entries, err := neighbors6(ctx, iface)
			return fmt.Sprintf("IPv6 neighbor table readable (%d mappings; entries may be stale)", len(entries)), err
		}},
	}
	runDiagnosticTasks(ctx, &r, tasks)
	r.Checks = append(r.Checks, DiagnosticCheck{Name: "remote_reachability", Status: "not_checked", Detail: "TCP, DNS, device replies and multicast delivery require a scan; opening a socket does not prove reachability"})
	r.DurationMS = time.Since(start).Milliseconds()
	return r, ctx.Err()
}
