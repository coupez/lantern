package fingerprints

import "testing"

func TestMailInputBoundaries(t *testing.T) {
	text := "[CAPABILITY IMAP4 IMAP4rev1 LITERAL+ ID AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5] foo.bar Cyrus IMAP4 v2.3.8-OS X Server 10.5:\t9G7013y server ready"
	m := Lookup(IMAPBanner, text)
	if m == nil || m.Input != text || m.Fields["service.version"] != "2.3.8" || m.Fields["host.name"] != "foo.bar" {
		t.Fatal(m)
	}
	for _, bad := range []string{"\r", "\n", "\r\n", "\x00", "\x1b", "\u202e", "\xff"} {
		if Lookup(IMAPBanner, text+bad) != nil || Lookup(POP3Banner, "Dovecot ready."+bad) != nil {
			t.Fatal("bad input matched", bad)
		}
	}
	if Lookup(POP3Banner, "Dovecot ready.\t") != nil {
		t.Fatal("POP3 accepted tab")
	}
}
