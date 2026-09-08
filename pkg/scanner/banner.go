package scanner

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// CleanText removes terminal and directional controls from untrusted strings.
// Preserve joiners used by ordinary text shaping and emoji graphemes.
func CleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || (unicode.In(r, unicode.Cf) && r != 0x200c && r != 0x200d) || r == 0x1b {
			return -1
		}
		return r
	}, s)
}
func bannerService(service string) bool {
	return service == "ssh" || service == "ftp" || service == "smtp" || service == "http"
}

// Four workers per device avoid serial timeout accumulation. All devices share
// slots, so banner connections cannot exceed the scan's limit (at most 32).
// A queued port receives its full exchange timeout once a slot becomes available.
func enrichBanners(ctx context.Context, d *Device, timeout time.Duration, slots chan struct{}, read func(context.Context, netip.Addr, Port, time.Duration) string) {
	var indices []int
	for i, p := range d.Ports {
		if bannerService(p.Service) {
			indices = append(indices, i)
		}
	}
	sort.Slice(indices, func(i, j int) bool { return d.Ports[indices[i]].Number < d.Ports[indices[j]].Number })
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(4, len(indices), cap(slots)) {
		wg.Go(func() {
			for i := range jobs {
				select {
				case <-ctx.Done():
					return
				case slots <- struct{}{}:
				}
				if ctx.Err() == nil {
					d.Ports[i].Banner = read(ctx, d.IP, d.Ports[i], timeout)
				}
				<-slots
			}
		})
	}
queue:
	for _, i := range indices {
		select {
		case <-ctx.Done():
			break queue
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
}

func readBanner(ctx context.Context, ip netip.Addr, p Port, timeout time.Duration) string {
	return readBannerWithDialer(ctx, ip, p, timeout, (&net.Dialer{}).DialContext)
}

func readBannerWithDialer(ctx context.Context, ip netip.Addr, p Port, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) string {
	if !bannerService(p.Service) || ctx.Err() != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := dial(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(p.Number))))
	if err != nil {
		return ""
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil || ctx.Err() != nil {
		return ""
	}
	if p.Service == "http" {
		_, err = io.WriteString(c, "HEAD / HTTP/1.0\r\nHost: "+net.JoinHostPort(ip.WithZone("").String(), strconv.Itoa(int(p.Number)))+"\r\nConnection: close\r\n\r\n")
		if err != nil {
			return ""
		}
	}
	return bannerResponse(c, p.Service)
}

// TCP reads need not align with lines. Read complete greetings/headers while
// bounding bytes, line length and header count, and never parse an HTTP body as headers.
func bannerResponse(src io.Reader, service string) string {
	limited := &io.LimitedReader{R: src, N: 8192}
	r := bufio.NewReaderSize(limited, 2048)
	first := ""
	for i := 0; i < 64; i++ {
		line, err := r.ReadSlice('\n')
		if err != nil && (err != io.EOF || limited.N == 0) {
			return first
		}
		text := strings.TrimSpace(string(line))
		if i == 0 {
			first = CleanText(text)
			if service != "http" && service != "ssh" {
				return first
			}
		}
		if service == "ssh" {
			// RFC 4253 section 4.2 permits lines before the identification.
			// Prefer its literal wire prefix; retain the first diagnostic if
			// no identification arrives within the existing exchange limits.
			if strings.HasPrefix(string(line), "SSH-") {
				return CleanText(text)
			}
		} else if i > 0 {
			if text == "" {
				return first
			}
			name, value, ok := strings.Cut(text, ":")
			if ok && strings.EqualFold(name, "server") {
				return CleanText(strings.TrimSpace(value))
			}
		}
		if err != nil {
			return first
		}
	}
	return first
}
