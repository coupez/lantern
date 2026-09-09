package android

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Keep the command constant: no caller text enters the remote shell. The &&
// chain ensures a failed property command cannot be hidden by a later success.
const propertyCommand = "/system/bin/getprop ro.product.manufacturer && /system/bin/getprop ro.product.model && /system/bin/getprop ro.product.device && /system/bin/getprop ro.build.fingerprint"

// Claim is an observation of one named Android property, not a retail catalog
// match or an independently authenticated physical-device identity.
type Claim struct {
	Field     string `json:"field"`
	Value     string `json:"value"`
	Key       string `json:"key"`
	Reference string `json:"reference"`
}

// Report identifies the ADB server and ephemeral transport handle used for this
// collection. Neither is a durable device ID or a LAN address binding.
type Report struct {
	Schema      int        `json:"schema"`
	Source      string     `json:"source"`
	Server      string     `json:"server"`
	TransportID uint64     `json:"transport_id"`
	CollectedAt string     `json:"collected_at"`
	Complete    bool       `json:"complete"`
	Properties  Properties `json:"properties"`
	Claims      []Claim    `json:"claims,omitempty"`
	Unavailable []string   `json:"unavailable,omitempty"`
}

// Read observes four allowlisted properties through an existing local ADB
// server and one explicitly selected, already-authorized transport. It does not
// start a server, enumerate devices, connect/pair a device, or retry selection.
// A modern shell-v2 service is required; legacy shell output is not accepted.
func Read(ctx context.Context, server netip.AddrPort, transportID uint64, timeout time.Duration) (report Report, err error) {
	report = Report{Schema: 1, Source: "adb", Server: server.String(), TransportID: transportID, CollectedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if !server.IsValid() || server.Port() == 0 || !server.Addr().IsLoopback() || server.Addr().Is4In6() || server.Addr().Zone() != "" || transportID == 0 || timeout <= 0 || timeout > 30*time.Second {
		return report, errors.New("ADB inventory requires a literal loopback server, positive transport ID and timeout of at most 30s")
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		} else if err != nil {
			// A socket deadline can fire just before the context timer gets
			// scheduled. Preserve the collection's deadline semantics.
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				err = context.DeadlineExceeded
			}
		}
	}()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.String())
	if err != nil {
		return report, fmt.Errorf("connect to existing local ADB server: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return report, err
	}
	request := func(service, phase string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.Copy(conn, strings.NewReader(fmt.Sprintf("%04x%s", len(service), service))); err != nil {
			return err
		}
		return readStatus(conn, phase)
	}
	if err := request("host:transport-id:"+strconv.FormatUint(transportID, 10), "transport selection"); err != nil {
		return report, err
	}
	if err := request("shell,v2,raw:"+propertyCommand, "shell-v2 property read"); err != nil {
		return report, err
	}
	output, err := readShell(conn)
	if err != nil {
		return report, fmt.Errorf("ADB property stream: %w", err)
	}
	properties, err := ParseProperties(output)
	if err != nil {
		return report, err
	}
	report.Properties, report.Complete = properties, true
	for _, field := range []struct{ name, key, value string }{
		{"manufacturer", "ro.product.manufacturer", properties.Manufacturer},
		{"model", "ro.product.model", properties.Model},
		{"device", "ro.product.device", properties.Device},
		{"build_fingerprint", "ro.build.fingerprint", properties.BuildFingerprint},
	} {
		if field.value == "" || strings.EqualFold(field.value, "unknown") {
			report.Unavailable = append(report.Unavailable, field.key)
			continue
		}
		report.Claims = append(report.Claims, Claim{Field: field.name, Value: field.value, Key: field.key, Reference: buildPropertyReference})
	}
	return report, nil
}

func readStatus(r io.Reader, phase string) error {
	var status [4]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return fmt.Errorf("ADB %s status: %w", phase, err)
	}
	switch string(status[:]) {
	case "OKAY":
		return nil
	case "FAIL":
		var length [4]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return errors.New("truncated ADB failure")
		}
		for _, b := range length {
			if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
				return errors.New("invalid ADB failure length")
			}
		}
		n, err := strconv.ParseUint(string(length[:]), 16, 16)
		if err != nil || n > 4096 {
			return errors.New("oversized ADB failure")
		}
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			return errors.New("truncated ADB failure")
		}
		// ADB failures can contain serial numbers. Keep remote text out of
		// returned errors, logs and reports.
		return fmt.Errorf("ADB %s refused; use an authorized transport with shell-v2 support", phase)
	default:
		return errors.New("invalid ADB status")
	}
}

func readShell(r io.Reader) ([]byte, error) {
	var output []byte
	for frames := 0; frames < 128; frames++ {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, fmt.Errorf("missing or truncated ADB shell exit: %w", err)
		}
		length := binary.LittleEndian.Uint32(header[1:])
		if length > 8200 {
			return nil, errors.New("ADB shell frame exceeds limit")
		}
		switch header[0] {
		case 1:
			if len(output)+int(length) > 8200 {
				return nil, errors.New("ADB property output exceeds limit")
			}
			start := len(output)
			output = append(output, make([]byte, int(length))...)
			if _, err := io.ReadFull(r, output[start:]); err != nil {
				return nil, fmt.Errorf("truncated ADB property output: %w", err)
			}
		case 2:
			if length != 0 {
				return nil, errors.New("ADB property command reported an error")
			}
		case 3:
			if length != 1 {
				return nil, errors.New("invalid ADB shell exit frame")
			}
			var exit [1]byte
			if _, err := io.ReadFull(r, exit[:]); err != nil || exit[0] != 0 {
				return nil, errors.New("ADB property command failed")
			}
			var trailing [1]byte
			if _, err := io.ReadFull(r, trailing[:]); err != io.EOF {
				return nil, errors.New("data or incomplete closure after ADB shell exit")
			}
			return output, nil
		default:
			return nil, errors.New("unexpected ADB shell channel")
		}
	}
	return nil, errors.New("too many ADB shell frames")
}
