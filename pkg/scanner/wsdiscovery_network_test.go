package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWSDNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			probes := testWSDProbes(t)
			server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetDeadline(time.Now().Add(2 * time.Second))
			results := make(chan error, 1)
			go func() {
				counts := map[string]int{}
				b := make([]byte, 8192)
				for range 3 * len(probes) {
					n, peer, err := server.ReadFromUDP(b)
					if err != nil {
						results <- err
						return
					}
					matched := false
					for _, p := range probes {
						if string(b[:n]) != string(p.packet) {
							continue
						}
						matched = true
						counts[p.id]++
						// Drop both initial transmissions and the first retries. The final
						// retransmission must carry the same bytes/MessageID and recover both.
						if counts[p.id] == 3 {
							bad := strings.ReplaceAll(wsdFixture(p), p.id, "urn:uuid:not-our-probe")
							for _, reply := range []string{bad, wsdFixture(p), wsdFixture(p)} {
								if _, err := server.WriteToUDP([]byte(reply), peer); err != nil {
									results <- err
									return
								}
							}
						}
					}
					if !matched {
						results <- fmt.Errorf("unexpected query %q", b[:n])
						return
					}
				}
				if len(counts) != len(probes) {
					results <- fmt.Errorf("missing protocol version: %v", counts)
					return
				}
				results <- nil
			}()
			client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(time.Second))
			ip := netip.MustParseAddr(address)
			start := time.Now()
			hits, err := collectWSD(context.Background(), client, server.LocalAddr().(*net.UDPAddr), netip.PrefixFrom(ip, ip.BitLen()), "", probes)
			if err != nil || len(hits) != 1 || hits[0].IP != ip || time.Since(start) > 1500*time.Millisecond {
				t.Fatal(hits, err, time.Since(start))
			}
			// The fake device reused the same response MessageID for both versions;
			// retransmissions and that duplicate response yield one endpoint record.
			device := Device{IP: hits[0].IP, Advertisements: hits[0].Ads, Evidence: []string{hits[0].Evidence}}
			normalizeAdvertisements(&device)
			device.Identity = identify(device.Advertisements)
			if !device.Responsive() || device.Identity == nil || device.Identity.Name != "Front Door" || len(device.Ports) != 0 {
				t.Fatal(device)
			}
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWSDCancelNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(30 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	first := make(chan struct{})
	go func() { b := make([]byte, 8192); server.ReadFromUDP(b); close(first); cancel() }()
	start := time.Now()
	hits, err := collectWSD(ctx, client, server.LocalAddr().(*net.UDPAddr), netip.MustParsePrefix("127.0.0.1/32"), "", testWSDProbes(t))
	if err != nil || len(hits) != 0 || time.Since(start) > time.Second {
		t.Fatal(hits, err, time.Since(start))
	}
	<-first
}

func TestWSDMulticastEngineNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	if os.Getenv("LANTERN_WSD_MULTICAST_TESTS") != "1" {
		t.Skip("isolated Linux multicast fixture")
	}
	networks, err := Networks()
	if err != nil {
		t.Fatal(err)
	}
	var iface *net.Interface
	var ip netip.Addr
	for _, network := range networks {
		candidate, e := net.InterfaceByName(network.Interface)
		if e == nil && candidate.Flags&net.FlagMulticast != 0 {
			iface = candidate
			ip = netip.MustParseAddr(network.Address)
			break
		}
	}
	if iface == nil {
		t.Fatal("no multicast interface")
	}
	server, err := net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 3702})
	if err != nil {
		t.Fatal(err)
	}
	server.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	defer func() {
		server.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	go func() {
		b := make([]byte, 8192)
		for range 12 {
			n, peer, err := server.ReadFromUDP(b)
			if err != nil {
				done <- err
				return
			}
			root, err := readWSDXML(b[:n])
			if err != nil {
				done <- err
				return
			}
			header, err := root.child(wsdSOAP, "Header", true)
			if err != nil {
				done <- err
				return
			}
			for _, version := range wsdVersions {
				action, _ := header.value(version.addressing, "Action", false)
				if action != version.discovery+"/Probe" {
					continue
				}
				id, err := header.value(version.addressing, "MessageID", true)
				if err != nil {
					done <- err
					return
				}
				packet := wsdFixture(wsdProbe{id: id, version: version})
				if _, err := server.WriteToUDP([]byte(packet), peer); err != nil {
					done <- err
					return
				}
			}
		}
		done <- nil
	}()
	o := Defaults()
	o.Target = netip.PrefixFrom(ip, 32)
	o.Interface = iface.Name
	o.Ports = nil
	o.ICMP = false
	o.Resolve = false
	o.Descriptions = false
	o.Timeout = 100 * time.Millisecond
	updates := []Device{}
	start := time.Now()
	report, err := (Engine{NeighborSource: noNeighbors}).Scan(context.Background(), o, func(event Event) {
		if event.Type == "device_update" {
			updates = append(updates, *event.Device)
		}
	})
	if err != nil || len(report.Devices) != 1 || len(updates) != 1 || time.Since(start) > 2*time.Second {
		t.Fatal(report, err, len(updates), time.Since(start))
	}
	for _, device := range []Device{report.Devices[0], updates[0]} {
		if !contains(device.Evidence, "ws-discovery") || device.Identity == nil || device.Identity.Name != "Front Door" || len(device.Ports) != 0 {
			t.Fatal(device)
		}
	}
	if len(report.IncompleteMethods) != 0 {
		t.Fatal(report.IncompleteMethods, report.Warnings)
	}
}
