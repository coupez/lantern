package fingerprints

import (
	"os"
	"os/exec"
	"sync"
	"testing"
)

// Each iteration starts with an unused index, as in a fresh process. Benchmarks
// are serial: no other lookup may run while the package state is reset.
func BenchmarkColdLookup(b *testing.B) {
	for _, tc := range []struct{ name, field, input string }{
		{"http", HTTPServer, "Apache/2.4.65"},
		{"ssh", SSHBanner, "OpenSSH_9.9p1 Ubuntu-3ubuntu1"},
		{"ftp", FTPBanner, "SYNOLOGY FTP server ready."},
		{"smtp", SMTPBanner, "foo.bar ESMTP Postfix (3.1.4)"},
		{"unknown-http", HTTPServer, "LanternUnknown/2026"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				once = sync.Once{}
				catalogs = nil
				Lookup(tc.field, tc.input)
			}
		})
	}
}

// A separate process guarantees no preceding test has initialized the index or
// compiled a rule. Mixed fields start together, then mutate only owned results.
func TestConcurrentColdLookups(t *testing.T) {
	if os.Getenv("LANTERN_TEST_COLD_LOOKUPS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConcurrentColdLookups$")
		cmd.Env = append(os.Environ(), "LANTERN_TEST_COLD_LOOKUPS=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cold lookup process: %v\n%s", err, output)
		}
		return
	}
	cases := []struct{ field, input, product string }{
		{HTTPServer, "Apache/2.4.65", "HTTPD"},
		{SSHBanner, "OpenSSH_9.9p1 Ubuntu-3ubuntu1", "OpenSSH"},
		{FTPBanner, "SYNOLOGY FTP server ready.", "SmbFTPD"},
		{SMTPBanner, "foo.bar ESMTP Postfix (3.1.4)", "Postfix"},
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 96; i++ {
		workers.Go(func() {
			<-start
			for j := 0; j < 16; j++ {
				if (i+j)%5 == 0 && Count() != 898 {
					t.Error("wrong catalog count")
				}
				tc := cases[(i+j)%len(cases)]
				match := Lookup(tc.field, tc.input)
				if match == nil || match.Input != tc.input || match.Field != tc.field || match.Fields["service.product"] != tc.product {
					t.Errorf("wrong cold/concurrent match for %s: %+v", tc.field, match)
					return
				}
				match.Fields["service.product"] = "caller mutation"
			}
		})
	}
	close(start)
	workers.Wait()
}
