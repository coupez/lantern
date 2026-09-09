package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const shellyMDNSReference = "https://shelly-api-docs.shelly.cloud/gen2/General/mDNS/"
const shellyInfoReference = "https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Shelly/#http-endpoint-shelly"
const maxShellyBytes = 16 * 1024

// Only the dedicated service opts a device into this read. Host names, generic
// HTTP TXT keys and advertised URLs never select an endpoint or another host.
func shellyDescriptionURL(peer netip.Addr, ad Advertisement) string {
	if ad.Protocol != "mdns" || !strings.EqualFold(ad.Service, "_shelly._tcp") || ad.Port == 0 {
		return ""
	}
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(peer.String(), strconv.Itoa(int(ad.Port))), Path: "/shelly"}
	return u.String()
}

func shellyGeneration(s string) bool {
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && n >= 2
}

func fetchShellyDescription(ctx context.Context, peer netip.Addr, raw string) (map[string]string, error) {
	b, err := fetchDeviceDocument(ctx, peer, raw, "application/json", maxShellyBytes)
	if err != nil {
		return nil, err
	}
	return parseShellyDescription(b)
}

// Preserve selected device-reported fields, rejecting ambiguous duplicate keys
// and malformed types. Unknown extension fields are accepted within the body cap.
func parseShellyDescription(b []byte) (map[string]string, error) {
	if len(b) > maxShellyBytes || !utf8.Valid(b) {
		return nil, errors.New("invalid or oversized Shelly device document")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected Shelly device object")
	}
	seen := map[string]bool{}
	fields := map[string]string{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return nil, errors.New("invalid or duplicate Shelly field")
		}
		seen[key] = true
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		switch key {
		case "gen":
			if !shellyGeneration(string(raw)) {
				return nil, errors.New("expected Shelly generation 2 or newer")
			}
			fields[key] = string(raw)
		case "id", "model", "name", "mac", "fw_id", "ver", "app", "profile":
			if key == "name" && string(raw) == "null" {
				continue
			}
			var value string
			if err := json.Unmarshal(raw, &value); err != nil || string(raw) == "null" || len(value) > 2048 {
				return nil, errors.New("invalid Shelly string field")
			}
			fields[key] = value
		}
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing Shelly document data")
	}
	if !shellyGeneration(fields["gen"]) || strings.TrimSpace(fields["id"]) == "" || strings.TrimSpace(fields["model"]) == "" {
		return nil, errors.New("incomplete Shelly device identity")
	}
	return fields, nil
}
