// Package observe extracts timestamped DHCP evidence from offline packet captures.
// An observation is neither a current scan result nor authenticated device identity.
package observe

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/coupez/lantern/pkg/capture"
	"github.com/coupez/lantern/pkg/dhcp"
)

var (
	ErrNotDHCP     = errors.New("not a DHCP datagram")
	ErrUnsupported = errors.New("unsupported packet encapsulation")
	ErrMalformed   = errors.New("malformed or incomplete packet")
)

// Observation keeps wire-source and DHCP client claims separate, including relays.
type Observation struct {
	Packet            int          `json:"packet"`
	Timestamp         time.Time    `json:"timestamp"`
	Section           uint32       `json:"section"`
	Interface         uint32       `json:"interface"`
	LinkType          uint16       `json:"link_type"`
	CapturedTruncated bool         `json:"captured_truncated,omitempty"`
	SourceIP          string       `json:"source_ip"`
	DestinationIP     string       `json:"destination_ip"`
	SourcePort        uint16       `json:"source_port"`
	DestinationPort   uint16       `json:"destination_port"`
	IPHopLimit        uint8        `json:"ip_hop_limit"` // Observed IPv4 TTL / IPv6 hop limit, not an inferred initial value.
	EthernetSource    string       `json:"ethernet_source,omitempty"`
	VLANs             []uint16     `json:"vlans,omitempty"`
	Message           dhcp.Message `json:"dhcp"`
}

// Summary counts capture records, not unique devices. Skipped records can contain
// evidence this importer could not decode; they do not prove absence of DHCP.
type Summary struct {
	Schema       int           `json:"schema"`
	Capture      capture.Stats `json:"capture"`
	Observations int           `json:"observations"`
	Ignored      int           `json:"ignored"`
	Unsupported  int           `json:"unsupported"`
	Malformed    int           `json:"malformed"`
	Truncated    int           `json:"truncated"`
	Incomplete   bool          `json:"incomplete"`
	Error        string        `json:"error,omitempty"`
}

// Read streams owned observations. It never sends packets, resolves addresses,
// merges clients across time/interfaces, or derives OS/model guesses.
func Read(ctx context.Context, r io.Reader, emit func(Observation) error) (Summary, error) {
	result := Summary{Schema: 1}
	index := 0
	stats, err := capture.Read(ctx, r, func(p capture.Packet) error {
		index++
		if p.Truncated {
			result.Truncated++
		}
		o, err := Decode(p)
		if err != nil {
			switch {
			case errors.Is(err, ErrNotDHCP):
				result.Ignored++
			case errors.Is(err, ErrUnsupported):
				result.Unsupported++
			default:
				result.Malformed++
			}
			return nil
		}
		o.Packet = index
		if emit != nil {
			if err := emit(o); err != nil {
				return err
			}
		}
		result.Observations++
		return nil
	})
	result.Capture = stats
	result.Incomplete = err != nil || result.Malformed > 0 || result.Unsupported > 0 || result.Truncated > 0
	if err != nil {
		result.Error = err.Error()
	}
	return result, err
}
