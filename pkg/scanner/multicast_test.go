package scanner

import (
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"testing"
)

func TestMDNSCorrelatesSRVAndAddress(t *testing.T) {
	host := dnsmessage.MustNewName("printer.local.")
	instance := dnsmessage.MustNewName("Office._ipp._tcp.local.")
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: instance, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.SRVResource{Port: 631, Target: host}}, {Header: dnsmessage.ResourceHeader{Name: instance, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"ty=Office Printer"}}}}, Additionals: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: host, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 5}}}}}
	b, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	r := newMDNSRecords()
	if !r.ingest(b) {
		t.Fatal("valid packet rejected")
	}
	hits := r.hits(netip.MustParsePrefix("192.168.1.0/24"))
	if len(hits) != 1 || len(hits[0].Ads) != 1 || hits[0].Ads[0].Port != 631 || hits[0].Ads[0].Properties["ty"] != "Office Printer" {
		t.Fatalf("%+v", hits)
	}
	if len(r.hits(netip.MustParsePrefix("10.0.0.0/24"))) != 0 {
		t.Fatal("out of range address admitted")
	}
}
func TestSSDP(t *testing.T) {
	ad, ok := parseSSDP([]byte("HTTP/1.1 200 OK\r\nSERVER: Camera/1.0\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nLOCATION: http://192.168.1.2/desc.xml\r\n\r\n"))
	if !ok || ad.Properties["server"] != "Camera/1.0" {
		t.Fatal(ad)
	}
	if _, ok = parseSSDP([]byte("HTTP/1.1 404 Not Found\nServer: no")); ok {
		t.Fatal("accepted invalid response")
	}
}
func FuzzMDNS(f *testing.F) {
	f.Add([]byte{0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := newMDNSRecords()
		r.ingest(b)
		r.hits(netip.MustParsePrefix("192.168.1.0/24"))
	})
}
