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
		r.hits(netip.MustParsePrefix("::/0"))
		r.followups(true)
	})
}

func TestMDNSFollowupsStayLocal(t *testing.T) {
	r := newMDNSRecords()
	r.pointers["_services._dns-sd._udp.local."] = []string{"_new._tcp.local.", "evil.example.", "instance._new._tcp.local."}
	r.pointers["_new._tcp.local."] = []string{"device._new._tcp.local.", "other._bad._tcp.local."}
	qs := r.followups()
	if len(qs) != 3 {
		t.Fatalf("expected service PTR + instance SRV/TXT, got %+v", qs)
	}
	for _, q := range qs {
		if q.Name.String() == "evil.example." {
			t.Fatal("escaped local discovery")
		}
	}
	r.services["device._new._tcp.local."] = dnsmessage.SRVResource{Target: dnsmessage.MustNewName("device.local."), Port: 9999}
	r.txt["device._new._tcp.local."] = map[string]string{}
	qs = r.followups()
	if len(qs) != 2 {
		t.Fatalf("expected service PTR + host A, got %+v", qs)
	}
	if serviceType("Living._fake.room._ipp._tcp.local.") != "_ipp._tcp.local." {
		t.Fatal("instance name corrupted service parsing")
	}
}
func TestMDNSTXTCaseAndFirstDuplicate(t *testing.T) {
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("Office._ipp._tcp.local."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"USB_MFG=Example", "usb_mfg=Incorrect", "USB_MDL=Printer 7"}}}}}
	b, _ := m.Pack()
	r := newMDNSRecords()
	r.ingest(b)
	p := r.txt["office._ipp._tcp.local."]
	if p["usb_mfg"] != "Example" || p["usb_mdl"] != "Printer 7" {
		t.Fatal(p)
	}
}
