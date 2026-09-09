package scanner

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxDescriptionBytes = 256 * 1024

// descriptionURL only permits the responding device itself, preventing an
// advertisement from turning the scanner into a proxy for arbitrary URLs.
func descriptionURL(raw string, peer netip.Addr) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("description requires a credential-free HTTP URL")
	}
	host, err := netip.ParseAddr(u.Hostname())
	if err != nil || host.Unmap().WithZone("") != peer.Unmap().WithZone("") || (host.Zone() != "" && host.Zone() != peer.Zone()) {
		return nil, errors.New("description URL must name the responding device's IP")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid description port")
		}
	}
	return u, nil
}
func fetchDescription(ctx context.Context, peer netip.Addr, raw string) ([]map[string]string, error) {
	b, err := fetchDeviceDocument(ctx, peer, raw, "text/xml, application/xml", maxDescriptionBytes)
	if err != nil {
		return nil, err
	}
	return parseDescription(string(b))
}

// fetchDeviceDocument is shared by read-only, discovery-triggered identity reads.
func fetchDeviceDocument(ctx context.Context, peer netip.Addr, raw, accept string, limit int64) ([]byte, error) {
	u, err := descriptionURL(raw, peer)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	// Pin the dial address as well as validating the URL; no DNS, proxies or redirects.
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16 * 1024, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(peer.String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Lantern/0.1")
	request.Header.Set("Accept", accept)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("description returned HTTP %d", response.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("device document exceeds %d bytes", limit)
	}
	return b, nil
}

// parseDescription reads direct device fields, keeping embedded UPnP devices
// separate. Depth and device count limits bound hostile or broken XML.
func parseDescription(s string) ([]map[string]string, error) {
	if len(s) > maxDescriptionBytes {
		return nil, errors.New("description exceeds 256 KiB")
	}
	decoder := xml.NewDecoder(strings.NewReader(s))
	depth := 0
	rootSeen := false
	type deviceFrame struct {
		depth  int
		fields map[string]string
	}
	stack := []deviceFrame{}
	devices := []map[string]string{}
	field := ""
	fieldDepth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if field != "" {
				return nil, fmt.Errorf("description field %s contains nested markup", field)
			}
			depth++
			if depth > 32 {
				return nil, errors.New("description XML is too deeply nested")
			}
			if depth == 1 {
				if rootSeen || t.Name.Local != "root" || t.Name.Space != "urn:schemas-upnp-org:device-1-0" {
					return nil, errors.New("expected a UPnP description root")
				}
				rootSeen = true
			}
			if t.Name.Local == "device" && t.Name.Space == "urn:schemas-upnp-org:device-1-0" {
				if len(devices) >= 64 {
					return nil, errors.New("too many embedded devices")
				}
				fields := map[string]string{}
				devices = append(devices, fields)
				stack = append(stack, deviceFrame{depth, fields})
			}
			field = ""
			if len(stack) > 0 && depth == stack[len(stack)-1].depth+1 && t.Name.Space == "urn:schemas-upnp-org:device-1-0" {
				switch t.Name.Local {
				case "friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType", "UDN":
					fields := stack[len(stack)-1].fields
					if _, exists := fields[t.Name.Local]; exists {
						return nil, fmt.Errorf("duplicate description field %s", t.Name.Local)
					}
					// Mark presence even for an empty first element. Only text
					// tokens within this one element may be concatenated.
					fields[t.Name.Local] = ""
					field = t.Name.Local
					fieldDepth = depth
				}
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return nil, errors.New("unexpected text outside description root")
			}
			if field != "" && depth == fieldDepth && len(stack) > 0 {
				m := stack[len(stack)-1].fields
				if len(m[field])+len(t) > 2048 {
					return nil, errors.New("description field is too long")
				}
				m[field] += string(t)
			}
		case xml.EndElement:
			field = ""
			if len(stack) > 0 && depth == stack[len(stack)-1].depth {
				stack = stack[:len(stack)-1]
			}
			depth--
		}
	}
	if !rootSeen || depth != 0 || len(devices) == 0 {
		return nil, errors.New("incomplete UPnP description")
	}
	for _, d := range devices {
		for k, v := range d {
			d[k] = strings.TrimSpace(CleanText(v))
		}
	}
	return devices, nil
}

// enrichDescriptions shares one deadline across at most four URLs per device.
func enrichDescriptions(ctx context.Context, d *Device, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type cached struct {
		devices []map[string]string
		err     error
	}
	cache := map[string]cached{}
	original := append([]Advertisement{}, d.Advertisements...)
	for _, ad := range original {
		if location := ippDescriptionURL(d.IP, ad); location != "" {
			key := "ipp:" + location
			if _, ok := cache[key]; ok || len(cache) >= 4 || ctx.Err() != nil {
				continue
			}
			fields, err := fetchIPPDescription(ctx, d.IP, location)
			cache[key] = cached{err: err}
			if err == nil {
				retainIPPDeviceID(fields)
				fields["location"] = location
				d.Advertisements = append(d.Advertisements, Advertisement{Protocol: "ipp", Service: "printer-attributes", Instance: ad.Instance, Port: ad.Port, Properties: fields})
			}
			continue
		}
		if ad.Protocol == "ssdp" && strings.EqualFold(ad.Service, "roku:ecp") {
			location := rokuDescriptionURL(d.IP, ad)
			key := "roku:" + location
			if location == "" || ctx.Err() != nil || len(cache) >= 4 {
				continue
			}
			if _, ok := cache[key]; ok {
				continue
			}
			fields, err := fetchRokuDescription(ctx, d.IP, location)
			cache[key] = cached{err: err}
			if err == nil {
				fields["location"] = location
				d.Advertisements = append(d.Advertisements, Advertisement{Protocol: "roku", Service: "device-info", Instance: "device-info", Properties: fields})
			}
			continue
		}
		if location := shellyDescriptionURL(d.IP, ad); location != "" {
			key := "shelly:" + location
			if _, ok := cache[key]; ok || len(cache) >= 4 || ctx.Err() != nil {
				continue
			}
			fields, err := fetchShellyDescription(ctx, d.IP, location)
			cache[key] = cached{err: err}
			if err == nil {
				fields["location"] = location
				d.Advertisements = append(d.Advertisements, Advertisement{Protocol: "shelly", Service: "device-info", Instance: fields["id"], Port: ad.Port, Properties: fields})
			}
			continue
		}
		if ad.Protocol != "ssdp" {
			continue
		}
		location := ad.Properties["location"]
		if location == "" {
			continue
		}
		result, ok := cache[location]
		if !ok {
			if len(cache) >= 4 || ctx.Err() != nil {
				continue
			}
			result.devices, result.err = fetchDescription(ctx, d.IP, location)
			cache[location] = result
		}
		if result.err != nil {
			continue
		}
		udn, _, _ := strings.Cut(ad.Properties["usn"], "::")
		// An embedded device's advertisement must not inherit the root model.
		for _, fields := range result.devices {
			if udn != "" && !strings.EqualFold(fields["UDN"], udn) {
				continue
			}
			props := make(map[string]string, len(fields)+1)
			for k, v := range fields {
				props[k] = v
			}
			props["location"] = location
			d.Advertisements = append(d.Advertisements, Advertisement{Protocol: "upnp", Instance: fields["UDN"], Service: fields["deviceType"], Properties: props})
			if udn == "" {
				break
			}
		}
	}
}
