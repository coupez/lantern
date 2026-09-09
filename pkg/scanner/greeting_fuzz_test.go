package scanner

import (
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/coupez/lantern/pkg/fingerprints"
)

// greetingChunks changes transport framing, including a final read that returns
// both bytes and EOF. Neither is allowed to change the observed greeting.
type greetingChunks struct {
	data        string
	chunk       int
	eofWithData bool
	read        int
}

func (r *greetingChunks) Read(p []byte) (int, error) {
	n := min(len(p), len(r.data), r.chunk)
	copy(p, r.data[:n])
	r.data = r.data[n:]
	r.read += n
	if len(r.data) == 0 && (n == 0 || r.eofWithData) {
		return n, io.EOF
	}
	return n, nil
}

func FuzzGreetingFraming(f *testing.F) {
	seeds := []string{
		"", "\r\n", "220", "220\r\n", "220 ready\r\n",
		"220-Synology FTP server ready.\r\nnotice\r\n220 Done\r\n",
		"120-Wait\r\n120 Ready soon\r\n220 Synology FTP server ready.\r\n",
		"220-foo.bar ESMTP Postfix (3.1.4)\r\n220 Ready\r\n",
		"220-hello\r\n221 wrong code\r\n220 Done\r\n",
		"* OK example.com Cyrus IMAP4 v2.3.7 server ready\r\n",
		"* PREAUTH [CAPABILITY IMAP4rev1] ready\r\n",
		"* BYE go away\r\n* OK ready\r\n",
		"+OK Dovecot ready.\r\n", "-ERR refused\r\n+OK Dovecot ready.\r\n",
		"+OK Dovecot ready.\x00\xff\r\n",
		"220 " + strings.Repeat("x", 506) + "\r\n",
		"* PREAUTH " + strings.Repeat("x", 2048) + "\r\n",
		strings.Repeat("120 "+strings.Repeat("x", 1018)+"\r\n", 8) + "220 ready\r\n",
	}
	for _, seed := range seeds {
		f.Add(seed, uint16(1), false)
		f.Add(seed, uint16(513), true)
	}
	f.Fuzz(func(t *testing.T, wire string, chunk uint16, eofWithData bool) {
		// Keep generated cases near the largest wire budget, including overflow.
		if len(wire) > 16384 {
			t.Skip()
		}
		for _, service := range []string{"ftp", "smtp", "imap", "pop3"} {
			want := observeBannerResponse(strings.NewReader(wire), service)
			reader := &greetingChunks{data: wire, chunk: int(chunk) + 1, eofWithData: eofWithData}
			got := observeBannerResponse(reader, service)
			if got != want {
				t.Fatalf("%s framing changed observation: chunk=%d EOF=%v got=%+v want=%+v", service, reader.chunk, eofWithData, got, want)
			}
			limit := 8192
			if service == "imap" {
				limit = fingerprints.MaxInputBytes + len("* PREAUTH ") + 2
			} else if service == "pop3" {
				limit = 512
			}
			if reader.read > limit || len(got.Value) > fingerprints.MaxInputBytes {
				t.Fatalf("%s exceeded budget: read=%d value=%d", service, reader.read, len(got.Value))
			}
			if !utf8.ValidString(got.Text) || CleanText(got.Text) != got.Text {
				t.Fatalf("%s unsafe display diagnostic: %q", service, got.Text)
			}
			if got.Field == "" && got.Value != "" {
				t.Fatalf("%s retained a value without a field", service)
			}
			if (service == "imap" || service == "pop3") && strings.Contains(wire, "\n") {
				// These protocols observe only the first line, even if a later
				// line contains a successful greeting or recognizable software.
				first := wire[:strings.IndexByte(wire, '\n')+1]
				if one := observeBannerResponse(strings.NewReader(first), service); one != got {
					t.Fatalf("%s later lines changed observation: %+v / %+v", service, one, got)
				}
			}
		}
	})
}
