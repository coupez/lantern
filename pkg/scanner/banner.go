package scanner

import (
	"bufio"
	"context"
	"github.com/coupez/lantern/pkg/fingerprints"
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

type bannerObservation struct {
	Text  string
	Field string
	Value string
}

// Retained for callers that only collect diagnostic text.
func enrichBanners(ctx context.Context, d *Device, timeout time.Duration, slots chan struct{}, read func(context.Context, netip.Addr, Port, time.Duration) string) {
	enrichBannerObservations(ctx, d, timeout, slots, func(ctx context.Context, ip netip.Addr, p Port, timeout time.Duration) bannerObservation {
		return bannerObservation{Text: read(ctx, ip, p, timeout)}
	})
}

// Four workers per device avoid serial timeout accumulation. All devices share
// slots, so banner connections cannot exceed the scan's limit (at most 32).
// A queued port receives its full exchange timeout once a slot becomes available.
func enrichBannerObservations(ctx context.Context, d *Device, timeout time.Duration, slots chan struct{}, read func(context.Context, netip.Addr, Port, time.Duration) bannerObservation) {
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
					observation := read(ctx, d.IP, d.Ports[i], timeout)
					d.Ports[i].Banner = observation.Text
					d.Ports[i].Fingerprint = fingerprints.Lookup(observation.Field, observation.Value)
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
	return readBannerObservationWithDialer(ctx, ip, p, timeout, dial).Text
}
func readBannerObservation(ctx context.Context, ip netip.Addr, p Port, timeout time.Duration) bannerObservation {
	return readBannerObservationWithDialer(ctx, ip, p, timeout, (&net.Dialer{}).DialContext)
}
func readBannerObservationWithDialer(ctx context.Context, ip netip.Addr, p Port, timeout time.Duration, dial func(context.Context, string, string) (net.Conn, error)) bannerObservation {
	if !bannerService(p.Service) || ctx.Err() != nil {
		return bannerObservation{}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := dial(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(p.Number))))
	if err != nil {
		return bannerObservation{}
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil || ctx.Err() != nil {
		return bannerObservation{}
	}
	if p.Service == "http" {
		_, err = io.WriteString(c, "HEAD / HTTP/1.0\r\nHost: "+net.JoinHostPort(ip.WithZone("").String(), strconv.Itoa(int(p.Number)))+"\r\nConnection: close\r\n\r\n")
		if err != nil {
			return bannerObservation{}
		}
	}
	return observeBannerResponse(c, p.Service)
}

// TCP reads need not align with lines. Read complete greetings/headers while
// bounding bytes, line length and header count, and never parse an HTTP body as headers.
func bannerResponse(src io.Reader, service string) string {
	return observeBannerResponse(src, service).Text
}
func observeBannerResponse(src io.Reader, service string) bannerObservation {
	limited := &io.LimitedReader{R: src, N: 8192}
	r := bufio.NewReaderSize(limited, 2048)
	first := bannerObservation{}
	validHTTP := false
	for i := 0; i < 64; i++ {
		line, err := r.ReadSlice('\n')
		if err != nil && (err != io.EOF || limited.N == 0) {
			return first
		}
		text := strings.TrimSpace(string(line))
		if i == 0 {
			first.Text = CleanText(text)
			validHTTP = validHTTPStatus(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"))
			if service != "http" && service != "ssh" {
				return first
			}
		}
		if service == "ssh" {
			// RFC 4253 section 4.2 permits lines before the identification.
			// Prefer its literal wire prefix; retain the first diagnostic if
			// no identification arrives within the existing exchange limits.
			if strings.HasPrefix(string(line), "SSH-") {
				observation := bannerObservation{Text: CleanText(text)}
				if err == nil && len(line) <= 255 {
					raw := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
					version, software, ok := strings.Cut(raw[4:], "-")
					if ok && (version == "2.0" || version == "1.99" || version == "1.5") {
						observation.Field, observation.Value = fingerprints.SSHBanner, software
					}
				}
				return observation
			}
		} else if i > 0 {
			if text == "" {
				return first
			}
			name, value, ok := strings.Cut(text, ":")
			if ok && strings.EqualFold(name, "server") {
				observation := bannerObservation{Text: CleanText(strings.TrimSpace(value))}
				raw := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
				rawName, rawValue, _ := strings.Cut(raw, ":")
				// Header names are ASCII; EqualFold alone accepts Unicode lookalikes.
				if err == nil && validHTTP && len(rawName) == len("server") && strings.EqualFold(rawName, "server") {
					observation.Field, observation.Value = fingerprints.HTTPServer, strings.Trim(rawValue, " \t")
				}
				return observation
			}
		}
		if err != nil {
			return first
		}
	}
	return first
}

func validHTTPStatus(line string) bool {
	if len(line) < 12 || (line[:9] != "HTTP/1.0 " && line[:9] != "HTTP/1.1 ") {
		return false
	}
	for _, c := range line[9:12] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(line) == 12 || line[12] == ' '
}
