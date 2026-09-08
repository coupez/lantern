package scanner

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

func TestBannerResponse(t *testing.T) {
	for _, tc := range []struct{ name, service, input, want string }{
		{"fragmented HTTP", "http", "HTTP/1.1 200 OK\r\nDate: fixture\r\nsErVeR: Lantern\r\n\r\n", "Lantern"},
		{"fragmented greeting", "ssh", "SSH-2.0-Lantern\r\n", "SSH-2.0-Lantern"},
		{"FTP greeting", "ftp", "220 Lantern\r\n", "220 Lantern"},
		{"SMTP greeting", "smtp", "220 Lantern ESMTP\r\n", "220 Lantern ESMTP"},
		{"EOF greeting", "ssh", "SSH-2.0-Lantern", "SSH-2.0-Lantern"},
		{"body is not headers", "http", "HTTP/1.1 200 OK\r\n\r\nServer: body\r\n", "HTTP/1.1 200 OK"},
		{"controls", "http", "HTTP/1.1 200 OK\r\nServer: Lantern\x1b\u202e\r\n", "Lantern"},
		{"long greeting", "ssh", strings.Repeat("a", 3000), ""},
		{"long header", "http", "HTTP/1.1 200 OK\r\nServer: " + strings.Repeat("a", 3000), "HTTP/1.1 200 OK"},
		{"header count", "http", "HTTP/1.1 200 OK\r\n" + strings.Repeat("X: x\r\n", 64) + "Server: hidden\r\n", "HTTP/1.1 200 OK"},
		{"byte budget", "http", "HTTP/1.1 200 OK\r\n" + strings.Repeat("X: "+strings.Repeat("a", 1000)+"\r\n", 9) + "Server: hidden\r\n", "HTTP/1.1 200 OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bannerResponse(iotest.OneByteReader(strings.NewReader(tc.input)), tc.service); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

type observedBannerConn struct {
	net.Conn
	deadline    time.Time
	deadlineErr error
	reading     chan struct{}
	once        sync.Once
}

func (c *observedBannerConn) SetDeadline(d time.Time) error {
	c.deadline = d
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	return c.Conn.SetDeadline(d)
}
func (c *observedBannerConn) Read(b []byte) (int, error) {
	if c.reading != nil {
		c.once.Do(func() { close(c.reading) })
	}
	return c.Conn.Read(b)
}

func TestBannerExchangeDeadlineAndFragmentedHTTP(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := &observedBannerConn{Conn: client}
	var dialDeadline time.Time
	request := make(chan string, 1)
	go func() {
		r := bufio.NewReader(server)
		var lines strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			lines.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		request <- lines.String()
		// net.Pipe writes rendezvous with reads: each fragment requires another read.
		for _, part := range []string{"HTTP/1.1 200 OK\r\n", "Ser", "ver: Fragmented", " fixture\r\n"} {
			if _, err := io.WriteString(server, part); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := readBannerWithDialer(ctx, netip.MustParseAddr("fe80::1%fixture"), Port{Number: 80, Service: "http"}, time.Minute,
		func(ctx context.Context, network, address string) (net.Conn, error) {
			dialDeadline, _ = ctx.Deadline()
			if network != "tcp" || address != "[fe80::1%fixture]:80" {
				t.Errorf("dial %s %s", network, address)
			}
			return c, nil
		})
	if got != "Fragmented fixture" {
		t.Fatal(got)
	}
	parentDeadline, _ := ctx.Deadline()
	if !c.deadline.Equal(dialDeadline) || !c.deadline.Equal(parentDeadline) {
		t.Fatalf("dial and I/O must use the same parent-bounded deadline: %v %v %v", dialDeadline, c.deadline, parentDeadline)
	}
	if got := <-request; got != "HEAD / HTTP/1.0\r\nHost: [fe80::1]:80\r\nConnection: close\r\n\r\n" {
		t.Fatal(got)
	}
}

func TestBannerOwnDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := &observedBannerConn{Conn: client}
	var dialDeadline time.Time
	started := time.Now()
	got := readBannerWithDialer(context.Background(), netip.MustParseAddr("127.0.0.1"), Port{Number: 22, Service: "ssh"}, 20*time.Millisecond,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialDeadline, _ = ctx.Deadline()
			// Consume the entire exchange budget during connection setup.
			<-ctx.Done()
			return c, nil
		})
	if got != "" || !c.deadline.Equal(dialDeadline) || dialDeadline.Sub(started) > 25*time.Millisecond {
		t.Fatalf("deadline was reset after dialing: %q %v %v", got, c.deadline, dialDeadline)
	}
}

func TestBannerCancellationClosesBlockedRead(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := &observedBannerConn{Conn: client, reading: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan string, 1)
	go func() {
		done <- readBannerWithDialer(ctx, netip.MustParseAddr("127.0.0.1"), Port{Number: 22, Service: "ssh"}, time.Minute,
			func(context.Context, string, string) (net.Conn, error) { return c, nil })
	}()
	select {
	case <-c.reading:
	case <-time.After(time.Second):
		t.Fatal("read never started")
	}
	cancel()
	select {
	case got := <-done:
		if got != "" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not stop read")
	}
}

func TestBannerDeadlineFailureAndUnsupportedService(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := &observedBannerConn{Conn: client, deadlineErr: errors.New("no deadlines")}
	dial := func(context.Context, string, string) (net.Conn, error) { return c, nil }
	if got := readBannerWithDialer(context.Background(), netip.MustParseAddr("127.0.0.1"), Port{Service: "ssh"}, time.Second, dial); got != "" {
		t.Fatal(got)
	}
	if _, err := client.Write([]byte("closed")); err == nil {
		t.Fatal("connection not closed")
	}
	readBannerWithDialer(context.Background(), netip.MustParseAddr("127.0.0.1"), Port{Service: "https"}, time.Second,
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("unsupported service dialed")
			return nil, nil
		})
}

func bannerFixture(n int) *Device {
	d := &Device{IP: netip.MustParseAddr("127.0.0.1")}
	for i := n; i > 0; i-- {
		d.Ports = append(d.Ports, Port{Number: uint16(i), Service: "http"})
	}
	d.Ports = append(d.Ports, Port{Number: 443, Service: "https"})
	return d
}

func TestBannerWorkerLimitsAndCoverage(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		devices, slots, wantActive int
	}{
		{"per device", 1, 32, 4}, {"whole scan", 3, 3, 3}, {"concurrency one", 2, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			slots := make(chan struct{}, tc.slots)
			started := make(chan struct{}, tc.devices*8)
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var active, peak, calls atomic.Int32
			read := func(_ context.Context, _ netip.Addr, p Port, timeout time.Duration) string {
				if p.Service != "http" || timeout != time.Second {
					t.Error("wrong banner request")
				}
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				calls.Add(1)
				started <- struct{}{}
				<-release
				return "fixture"
			}
			var wg sync.WaitGroup
			var devices []*Device
			for range tc.devices {
				d := bannerFixture(8)
				devices = append(devices, d)
				wg.Go(func() { enrichBanners(context.Background(), d, time.Second, slots, read) })
			}
			for range tc.wantActive {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("workers did not start")
				}
			}
			unblock()
			wg.Wait()
			if peak.Load() != int32(tc.wantActive) || active.Load() != 0 || calls.Load() != int32(tc.devices*8) || len(slots) != 0 {
				t.Fatalf("peak=%d active=%d calls=%d slots=%d", peak.Load(), active.Load(), calls.Load(), len(slots))
			}
			for _, d := range devices {
				for _, p := range d.Ports {
					if (p.Service == "http" && p.Banner != "fixture") || (p.Service == "https" && p.Banner != "") {
						t.Fatal(p)
					}
				}
			}
		})
	}
}

func TestBannerWorkerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slots := make(chan struct{}, 1)
	started := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		enrichBanners(ctx, bannerFixture(100), time.Minute, slots,
			func(ctx context.Context, _ netip.Addr, _ Port, _ time.Duration) string {
				calls.Add(1)
				close(started)
				<-ctx.Done()
				return ""
			})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers did not join")
	}
	if calls.Load() != 1 || len(slots) != 0 {
		t.Fatal(calls.Load(), len(slots))
	}
}

func BenchmarkStalledBanners(b *testing.B) {
	read := func(ctx context.Context, _ netip.Addr, _ Port, timeout time.Duration) string {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		<-ctx.Done()
		return ""
	}
	for _, parallel := range []bool{false, true} {
		name := "serial"
		if parallel {
			name = "bounded_parallel"
		}
		b.Run(name, func(b *testing.B) {
			d := bannerFixture(8)
			slots := make(chan struct{}, 32)
			for b.Loop() {
				if parallel {
					enrichBanners(context.Background(), d, 2*time.Millisecond, slots, read)
				} else {
					for _, p := range d.Ports {
						if bannerService(p.Service) {
							read(context.Background(), d.IP, p, 2*time.Millisecond)
						}
					}
				}
			}
		})
	}
}

func TestBannerStallsDoNotStarveLaterPorts(t *testing.T) {
	d := bannerFixture(8)
	for i := range d.Ports[:8] {
		d.Ports[i].Service = "ssh"
	}
	var calls atomic.Int32
	enrichBanners(context.Background(), d, 20*time.Millisecond, make(chan struct{}, 4),
		func(ctx context.Context, ip netip.Addr, p Port, timeout time.Duration) string {
			calls.Add(1)
			client, server := net.Pipe()
			defer server.Close()
			if p.Number == 8 {
				go func() { io.WriteString(server, "SSH-2.0-Late_fixture\r\n") }()
			}
			return readBannerWithDialer(ctx, ip, p, timeout,
				func(context.Context, string, string) (net.Conn, error) { return client, nil })
		})
	if calls.Load() != 8 || d.Ports[0].Banner != "SSH-2.0-Late_fixture" {
		t.Fatalf("later ports lost their response budget: calls=%d ports=%+v", calls.Load(), d.Ports)
	}
}

func TestBannerCancellationWhileWaitingForSharedSlot(t *testing.T) {
	slots := make(chan struct{}, 2)
	slots <- struct{}{}
	slots <- struct{}{} // Other devices occupy the entire scan budget.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		enrichBanners(ctx, bannerFixture(100), time.Minute, slots,
			func(context.Context, netip.Addr, Port, time.Duration) string {
				t.Error("dialed without a free slot")
				return ""
			})
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not release waiting workers")
	}
	if len(slots) != 2 {
		t.Fatal("released another device's slots")
	}
}
