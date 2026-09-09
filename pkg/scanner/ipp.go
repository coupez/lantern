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

	"github.com/coupez/lantern/pkg/ipp"
)

const maxIPPBytes int64 = 256 * 1024

// ippDescriptionURL accepts only a printer's own DNS-SD service endpoint and
// resource path. An advertisement never supplies a host, query, or redirect.
func ippDescriptionURL(peer netip.Addr, ad Advertisement) string {
	if !validIPPPeer(peer) || ad.Protocol != "mdns" || ad.Port == 0 {
		return ""
	}
	scheme := ""
	switch {
	case strings.EqualFold(ad.Service, "_ipp._tcp"):
		scheme = "http"
	case strings.EqualFold(ad.Service, "_ipps._tcp"):
		scheme = "https"
	default:
		return ""
	}
	rp, ok := ad.Properties["rp"]
	if !ok || !validIPPResourcePath(rp) {
		return ""
	}
	if !strings.HasPrefix(rp, "/") {
		rp = "/" + rp
	}
	path, _ := url.PathUnescape(rp)
	return (&url.URL{Scheme: scheme, Host: net.JoinHostPort(peer.String(), strconv.Itoa(int(ad.Port))), Path: path, RawPath: rp}).String()
}

func validIPPResourcePath(rp string) bool {
	if rp == "" || len(rp) > 2048 || !utf8.ValidString(rp) || CleanText(rp) != rp || strings.ContainsAny(rp, "\\?#") {
		return false
	}
	u, err := url.Parse(rp)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasPrefix(rp, "//") {
		return false
	}
	// DNS-SD supplies a URI path, so keep valid percent escapes without
	// double-encoding them. Validate repeated escapes conservatively because
	// the remote HTTP stack ultimately chooses its path normalization rules.
	decoded := rp
	for range 4 {
		decoded, err = url.PathUnescape(decoded)
		if err != nil || !utf8.ValidString(decoded) || CleanText(decoded) != decoded || strings.ContainsAny(decoded, "\\?#") {
			return false
		}
		for _, component := range strings.Split(decoded, "/") {
			if component == "." || component == ".." {
				return false
			}
		}
		if !strings.Contains(decoded, "%") {
			break
		}
	}
	return !strings.Contains(decoded, "%")
}

func validIPPPeer(peer netip.Addr) bool {
	return peer.IsValid() && !peer.IsUnspecified() && !peer.IsMulticast()
}

func ippURL(raw string, peer netip.Addr) (*url.URL, error) {
	if !validIPPPeer(peer) {
		return nil, errors.New("invalid IPP peer")
	}
	if strings.ContainsAny(raw, "?#") {
		return nil, errors.New("IPP URL must not contain query or fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("IPP requires a credential-free HTTP(S) URL")
	}
	host, err := netip.ParseAddr(u.Hostname())
	if err != nil || host.Unmap().WithZone("") != peer.Unmap().WithZone("") || (host.Zone() != "" && host.Zone() != peer.Zone()) {
		return nil, errors.New("IPP URL must name the responding device's IP")
	}
	if u.Path == "" || !validIPPResourcePath(u.EscapedPath()) {
		return nil, errors.New("invalid IPP resource path")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid IPP port")
		}
	}
	return u, nil
}

// fetchIPPDescription performs one discovery-authorized Get-Printer-Attributes
// request. IPPS uses certificate-unverified TLS because the DNS-SD observation
// pins the peer but is not an authenticated identity assertion.
func fetchIPPDescription(ctx context.Context, peer netip.Addr, raw string) (map[string]string, error) {
	u, err := ippURL(raw, peer)
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
	requestURI := *u
	if requestURI.Scheme == "https" {
		requestURI.Scheme = "ipps"
	} else {
		requestURI.Scheme = "ipp"
	}
	const requestID int32 = 1
	payload, err := ipp.Request(requestURI.String(), requestID)
	if err != nil {
		return nil, err
	}
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
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // #nosec G402 -- peer-pinned discovery observation; retained below.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Lantern/0.1")
	request.Header.Set("Content-Type", "application/ipp")
	request.Header.Set("Accept", "application/ipp")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPP returned HTTP %d", response.StatusCode)
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(contentType, "application/ipp") {
		return nil, errors.New("IPP response is not application/ipp")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, maxIPPBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxIPPBytes {
		return nil, fmt.Errorf("IPP response exceeds %d bytes", maxIPPBytes)
	}
	fields, err := ipp.ParseResponse(b, requestID)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		fields["transport"] = "tls-unverified"
	}
	return fields, nil
}
