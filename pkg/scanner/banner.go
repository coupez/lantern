package scanner

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// CleanText removes terminal control characters from untrusted network strings.
func CleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) || r == 0x1b {
			return -1
		}
		return r
	}, s)
}
func readBanner(ctx context.Context, ip netip.Addr, p Port, timeout time.Duration) string {
	if p.Service != "ssh" && p.Service != "ftp" && p.Service != "smtp" && p.Service != "http" {
		return ""
	}
	c, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(int(p.Number))))
	if err != nil {
		return ""
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(timeout))
	if p.Service == "http" {
		_, err = c.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + ip.String() + "\r\nConnection: close\r\n\r\n"))
		if err != nil {
			return ""
		}
	}
	b := make([]byte, 2048)
	n, _ := c.Read(b)
	s := string(b[:n])
	if p.Service == "http" {
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				return CleanText(strings.TrimSpace(line[7:]))
			}
		}
	}
	line, _, _ := strings.Cut(s, "\n")
	return CleanText(strings.TrimSpace(line))
}
