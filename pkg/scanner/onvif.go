package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/coupez/lantern/pkg/onvif"
)

const (
	maxONVIFBytes = 32 * 1024
	onvifAction   = "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
)

var onvifEligibleTypes = map[string]bool{
	"{http://www.onvif.org/ver10/device/wsdl}Device":                   true,
	"{http://www.onvif.org/ver10/network/wsdl}NetworkVideoTransmitter": true,
}

// onvifDescriptionURLs returns only literal same-peer XAddrs advertised by a
// matching WS-Discovery ProbeMatch. It never synthesizes a device-service path.
func onvifDescriptionURLs(peer netip.Addr, ad Advertisement) []string {
	if !validIPPPeer(peer) || ad.Protocol != "ws-discovery" || ad.Service != "probe-match" || !eligibleONVIFTypes(ad.Properties["types"]) {
		return nil
	}
	candidates := strings.Fields(ad.Properties["xaddrs"])
	if len(candidates) > 32 {
		return nil
	}
	seen := make(map[string]bool, len(candidates))
	urls := make([]string, 0, min(4, len(candidates)))
	for _, raw := range candidates {
		u, err := onvifURL(raw, peer)
		if err != nil {
			continue
		}
		endpoint := u.String()
		if !seen[endpoint] {
			seen[endpoint] = true
			urls = append(urls, endpoint)
			if len(urls) == 4 {
				break
			}
		}
	}
	return urls
}

func eligibleONVIFTypes(types string) bool {
	for _, typ := range strings.Fields(types) {
		if onvifEligibleTypes[typ] {
			return true
		}
	}
	return false
}

func onvifURL(raw string, peer netip.Addr) (*url.URL, error) {
	if !validIPPPeer(peer) || raw == "" || len(raw) > 2048 || !utf8.ValidString(raw) || CleanText(raw) != raw || strings.ContainsAny(raw, "?#") {
		return nil, errors.New("invalid ONVIF endpoint")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("ONVIF requires a credential-free HTTP(S) endpoint")
	}
	host, err := netip.ParseAddr(u.Hostname())
	if err != nil || host.Unmap().WithZone("") != peer.Unmap().WithZone("") || (host.Zone() != "" && host.Zone() != peer.Zone()) {
		return nil, errors.New("ONVIF endpoint must name the responding device IP")
	}
	if u.Path == "" || !validIPPResourcePath(u.EscapedPath()) {
		return nil, errors.New("invalid ONVIF endpoint path")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid ONVIF endpoint port")
		}
	}
	return u, nil
}

// fetchONVIFDescription makes one unauthenticated GetDeviceInformation call.
// Returned manufacturer/model fields are endpoint claims, not authenticated
// hardware identity; credentialed retries and WS-Security are deliberately absent.
func fetchONVIFDescription(ctx context.Context, peer netip.Addr, raw string) (map[string]string, error) {
	u, err := onvifURL(raw, peer)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	payload := onvif.Request()
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 * 1024,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(peer.String(), port))
		},
	}
	if u.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // #nosec G402 -- unverified discovery transport is labeled below.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Lantern/0.1")
	request.Header.Set("Content-Type", "application/soap+xml; charset=utf-8; action=\""+onvifAction+"\"")
	request.Header.Set("Accept", "application/soap+xml")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ONVIF returned HTTP %d", response.StatusCode)
	}
	if !validONVIFContentType(response.Header.Get("Content-Type")) {
		return nil, errors.New("ONVIF response is not SOAP 1.2")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, maxONVIFBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxONVIFBytes {
		return nil, fmt.Errorf("ONVIF response exceeds %d bytes", maxONVIFBytes)
	}
	fields, err := onvif.ParseResponse(b)
	if err != nil {
		return nil, err
	}
	fields["authentication"] = "none"
	if u.Scheme == "https" {
		fields["transport"] = "tls-unverified"
	}
	return fields, nil
}

func validONVIFContentType(raw string) bool {
	contentType, params, err := mime.ParseMediaType(raw)
	if err != nil || !strings.EqualFold(contentType, "application/soap+xml") {
		return false
	}
	return params["charset"] == "" || strings.EqualFold(params["charset"], "utf-8")
}
