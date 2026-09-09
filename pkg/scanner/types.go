// Package scanner is a cancellable network discovery engine independent of the CLI.
package scanner

import (
	"context"
	"github.com/coupez/lantern/pkg/fingerprints"
	"github.com/coupez/lantern/pkg/vendors"
	"net/netip"
	"time"
)

type Port struct {
	Fingerprint *fingerprints.Match `json:"fingerprint,omitempty"`
	Number      uint16              `json:"port"`
	Service     string              `json:"service"`
	Banner      string              `json:"banner,omitempty"`
}
type Device struct {
	Identity       *Identity       `json:"identity,omitempty"`
	Advertisements []Advertisement `json:"advertisements,omitempty"`
	IP             netip.Addr      `json:"ip"`
	MAC            string          `json:"mac,omitempty"`
	Vendor         vendors.Match   `json:"vendor"`
	Names          []string        `json:"names,omitempty"`
	Ports          []Port          `json:"ports,omitempty"`
	Kind           string          `json:"kind,omitempty"`
	Evidence       []string        `json:"evidence"`
	LatencyMS      float64         `json:"latency_ms,omitempty"`
}

// ScanCoverage records requested probes/enrichment, not successful responses.
// A nil Report.Coverage denotes a legacy snapshot with unknown configuration.
type ScanCoverage struct {
	TCPPorts     []uint16 `json:"tcp_ports"`
	ICMP         bool     `json:"icmp"`
	ARP          bool     `json:"arp"`
	NDP          bool     `json:"ndp"`
	Multicast    bool     `json:"multicast"`
	NetBIOS      bool     `json:"netbios"`
	ReverseDNS   bool     `json:"reverse_dns"`
	Descriptions bool     `json:"descriptions"`
	Banners      bool     `json:"banners"`
	AllHosts     bool     `json:"all_hosts"`
}

type Report struct {
	Coverage  *ScanCoverage `json:"coverage,omitempty"`
	ICMP      *ICMPStats    `json:"icmp,omitempty"`
	Interface string        `json:"interface,omitempty"`
	// AddressMode is enumerated for finite ranges or discovered for sparse IPv6.
	AddressMode string    `json:"address_mode,omitempty"`
	Schema      int       `json:"schema"`
	Target      string    `json:"target"`
	Started     time.Time `json:"started"`
	DurationMS  int64     `json:"duration_ms"`
	Targets     int       `json:"targets"`
	Probed      int       `json:"probed"`
	Devices     []Device  `json:"devices"`
	Warnings    []string  `json:"warnings,omitempty"`
	Cancelled   bool      `json:"cancelled,omitempty"`
	// IncompleteMethods names discovery passes with reported errors or exhausted
	// budgets: tcp, icmp, arp, ndp, multicast, netbios, neighbors, candidates.
	// Sorted and unique. Absence is not proof of exhaustive discovery; silent
	// hosts and unsuccessful optional enrichment can still leave fields empty.
	IncompleteMethods []string `json:"incomplete_methods,omitempty"`
	// Error marks a failed scan with usable partial results, never an input-validation error.
	Error string `json:"error,omitempty"`
}

// Event callbacks are serialized and synchronous. Device snapshots are owned by
// the recipient and remain independent of later events and the returned report.
// progress counts TCP jobs during discovery/ports; the enrichment phase and
// device_update count processed devices. A processed device can still have missing fields.
type Event struct {
	Phase     string  `json:"phase,omitempty"`
	Type      string  `json:"type"`
	Device    *Device `json:"device,omitempty"`
	Completed int     `json:"completed,omitempty"`
	Total     int     `json:"total,omitempty"`
	Message   string  `json:"message,omitempty"`
}
type Options struct {
	// Interface selects local discovery and neighbor/local-address evidence,
	// and scopes link-local IPv6 probes. TCP connects use normal OS routing.
	Interface   string
	Target      netip.Prefix
	Ports       []uint16
	Concurrency int
	Timeout     time.Duration
	Resolve     bool
	ICMP        bool
	// NetBIOS enables unicast IPv4 node-status discovery without authentication.
	NetBIOS bool
	// ARP enables direct IPv4 neighbor discovery; requires raw link access.
	ARP bool
	// NDP enables direct IPv6 neighbor solicitation on the local Ethernet link.
	NDP     bool
	Banners bool
	// Descriptions enables bounded UPnP, Shelly, Roku and IPP identity reads.
	Descriptions bool
	Multicast    bool
	AllHosts     bool
	MaxHosts     int
}

func Defaults() Options {
	return Options{Descriptions: true, Multicast: true, Concurrency: 512, Timeout: 300 * time.Millisecond, Resolve: true, ICMP: true, MaxHosts: 4096, Ports: []uint16{22, 53, 80, 443, 445, 554, 631, 3389, 5000, 7000, 8008, 8080, 8443, 9100}}
}

type Dialer interface {
	Probe(context.Context, netip.Addr, uint16, time.Duration) (bool, bool, time.Duration, error)
}

var Services = map[uint16]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 554: "rtsp", 631: "ipp", 993: "imaps", 995: "pop3s", 1883: "mqtt", 3000: "http", 3306: "mysql", 3389: "rdp", 5000: "http", 5353: "mdns", 5432: "postgres", 5900: "vnc", 6379: "redis", 7000: "airplay", 8008: "http", 8009: "cast", 8080: "http", 8443: "https", 9000: "http", 9100: "printer"}

// Responsive reports active discovery evidence or a local-interface observation
// in this record. It does not guarantee that every service is reachable.
func (d Device) Responsive() bool {
	for _, e := range d.Evidence {
		switch e {
		case "arp", "ndp", "icmp", "tcp-open", "tcp-refused", "mdns", "ssdp", "ws-discovery", "netbios", "local-interface":
			return true
		}
	}
	return false
}
