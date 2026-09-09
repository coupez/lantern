package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A standalone SOAP fixture, independent of the production codec.
const onvifResponseFixture = `<?xml version="1.0"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://www.onvif.org/ver10/device/wsdl"><env:Body><d:GetDeviceInformationResponse><d:Manufacturer>Example</d:Manufacturer><d:Model>Camera 7</d:Model><d:FirmwareVersion>1.2.3</d:FirmwareVersion><d:SerialNumber>do-not-store-serial</d:SerialNumber><d:HardwareId>do-not-store-hardware</d:HardwareId></d:GetDeviceInformationResponse></env:Body></env:Envelope>`

func onvifAdvertisement(endpoint string) Advertisement {
	return Advertisement{Protocol: "ws-discovery", Service: "probe-match", Instance: "urn:uuid:synthetic-onvif", Properties: map[string]string{"types": "{http://www.onvif.org/ver10/device/wsdl}Device", "xaddrs": endpoint}}
}
func checkONVIFRequest(t *testing.T, r *http.Request) {
	t.Helper()
	b, e := io.ReadAll(io.LimitReader(r.Body, 4097))
	if e != nil || len(b) > 4096 {
		t.Error("bad request body", e)
		return
	}
	content, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != "POST" || content != "application/soap+xml" || e != nil || params["action"] != "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		t.Error("unexpected request", r.Method, r.Header)
	}
	var envelope struct {
		XMLName xml.Name
		Body    struct {
			XMLName     xml.Name
			Information struct {
				XMLName  xml.Name
				Contents string `xml:",innerxml"`
			} `xml:"http://www.onvif.org/ver10/device/wsdl GetDeviceInformation"`
		} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
	}
	if err := xml.Unmarshal(b, &envelope); err != nil || envelope.XMLName != (xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Envelope"}) || envelope.Body.Information.XMLName.Local != "GetDeviceInformation" || strings.TrimSpace(envelope.Body.Information.Contents) != "" {
		t.Errorf("invalid SOAP request: %s (%v)", b, err)
	}
	if strings.Contains(string(b), "Security") || strings.Contains(string(b), "Username") || strings.Contains(string(b), "Password") {
		t.Error("unexpected authentication material")
	}
}
func TestONVIFIdentityNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			var hits atomic.Int32
			server := shellyHTTPFixture(t, address, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				checkONVIFRequest(t, r)
				if r.URL.EscapedPath() != "/services/Camera%20One" {
					t.Error("rewritten advertised path", r.URL)
				}
				w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
				fmt.Fprint(w, onvifResponseFixture)
			}))
			ad := onvifAdvertisement(server.URL + "/services/Camera%20One")
			d := Device{IP: netip.MustParseAddr(address), Advertisements: []Advertisement{ad, ad}, MAC: "02:aa:bb:cc:dd:ee"}
			enrichDescriptions(context.Background(), &d, time.Second)
			normalizeAdvertisements(&d)
			d.Identity = identify(d.Advertisements)
			if hits.Load() != 1 || d.Identity == nil || d.Identity.Model != "Camera 7" || d.Identity.Manufacturer != "Example" || d.Identity.FirmwareVersion != "1.2.3" || d.Identity.Firmware != "" || len(d.Ports) != 0 || d.MAC != "02:aa:bb:cc:dd:ee" || inferKind(d) != "device" {
				t.Fatal(d, d.Identity, hits.Load())
			}
			for _, ad := range d.Advertisements {
				for k, v := range ad.Properties {
					if strings.Contains(k, "Serial") || strings.Contains(k, "Hardware") || strings.Contains(v, "do-not-store") {
						t.Fatal("retained discarded identity", ad)
					}
				}
			}
		})
	}
}
func TestONVIFTLSNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkONVIFRequest(t, r)
		w.Header().Set("Content-Type", "application/soap+xml")
		fmt.Fprint(w, onvifResponseFixture)
	}))
	defer server.Close()
	d := Device{IP: netip.MustParseAddr("127.0.0.1"), Advertisements: []Advertisement{onvifAdvertisement(server.URL + "/service")}}
	enrichDescriptions(context.Background(), &d, time.Second)
	id := identify(d.Advertisements)
	if id == nil || id.Model != "Camera 7" {
		t.Fatal(id)
	}
	seen := map[string]bool{}
	for _, c := range id.Claims {
		if c.Basis == "transport" {
			seen[c.Value] = true
		}
	}
	if !seen["TLS certificate not verified"] || !seen["No credentials supplied"] {
		t.Fatal(id)
	}
}
func TestONVIFFailureAndBudgetNetworkIntegration(t *testing.T) {
	requireNetwork(t)
	var hits, mode, ippHits atomic.Int32
	shutdown := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		hits.Add(1)
		switch mode.Load() {
		case 1:
			w.Header().Set("WWW-Authenticate", `Digest realm="fixture", nonce="fixture"`)
			w.WriteHeader(401)
		case 2:
			http.Redirect(w, r, "/admin", 302)
		case 3:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, onvifResponseFixture)
		case 4:
			w.Header().Set("Content-Type", "application/soap+xml")
			fmt.Fprint(w, strings.Repeat("x", 32769))
		case 5:
			select {
			case <-r.Context().Done():
			case <-shutdown:
			}
		case 6:
			w.Header().Set("Content-Type", "application/soap+xml")
			fmt.Fprint(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault/></s:Body></s:Envelope>`)
		default:
			if r.Header.Get("Content-Type") == "application/ipp" {
				ippHits.Add(1)
				w.Header().Set("Content-Type", "application/ipp")
				w.Write(ippResponseFixture(1))
			} else {
				w.Header().Set("Content-Type", "application/soap+xml")
				fmt.Fprint(w, onvifResponseFixture)
			}
		}
	}))
	defer server.Close()
	defer close(shutdown)
	peer := netip.MustParseAddr("127.0.0.1")
	for i := int32(1); i <= 6; i++ {
		mode.Store(i)
		before := hits.Load()
		d := Device{IP: peer, Advertisements: []Advertisement{onvifAdvertisement(server.URL + "/service")}}
		start := time.Now()
		enrichDescriptions(context.Background(), &d, 100*time.Millisecond)
		if hits.Load() != before+1 || len(d.Advertisements) != 1 || time.Since(start) > time.Second {
			t.Fatal("failure lost original or retried", i, d, hits.Load()-before)
		}
	}
	mode.Store(0)
	before := hits.Load()
	if _, err := fetchONVIFDescription(context.Background(), netip.MustParseAddr("192.0.2.8"), server.URL+"/service"); err == nil || hits.Load() != before {
		t.Fatal("off-peer fetch")
	}
	// The IPP request consumes the first of the common four requests; ONVIF gets three.
	ipAd := ippAdvertisement(t, server.URL, "_ipp._tcp", "ipp/print")
	var urls []string
	for i := 0; i < 8; i++ {
		urls = append(urls, fmt.Sprintf("%s/service-%d", server.URL, i))
	}
	d := Device{IP: peer, Advertisements: []Advertisement{ipAd, onvifAdvertisement(strings.Join(urls, " "))}}
	enrichDescriptions(context.Background(), &d, time.Second)
	if hits.Load()-before != 4 || ippHits.Load() != 1 {
		t.Fatal("shared request budget", hits.Load()-before, ippHits.Load())
	}
}
