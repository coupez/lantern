package scanner

import (
	"bufio"
	"io"
	"strings"

	"github.com/coupez/lantern/pkg/fingerprints"
)

// Parse complete 220 greetings without sending commands. FTP may precede its
// greeting with 120, and may leave intermediate multiline text unprefixed. SMTP
// requires 220 on every line. Partial/malformed responses retain only the first
// display diagnostic, never a fingerprintable field.
func observeGreetingResponse(src io.Reader, service string) bannerObservation {
	limited := &io.LimitedReader{R: src, N: 8192}
	reader := bufio.NewReaderSize(limited, 2048)
	first := bannerObservation{}
	code, greetingText := "", ""
	var parts []string
	size := 0
	for i := 0; i < 64; i++ {
		line, err := reader.ReadSlice('\n')
		if err != nil && (err != io.EOF || limited.N == 0) {
			return first
		}
		if i == 0 {
			first.Text = CleanText(strings.TrimSpace(string(line)))
		}
		if err != nil || !strings.HasSuffix(string(line), "\r\n") || service == "smtp" && len(line) > 512 {
			return first
		}
		raw := string(line[:len(line)-2])
		text, done := raw, false
		if code == "" {
			if len(raw) < 3 || raw[:3] != "220" && (service != "ftp" || raw[:3] != "120") {
				return first
			}
			code = raw[:3]
			if code == "220" {
				greetingText = CleanText(strings.TrimSpace(raw))
			}
		} else if service == "ftp" && !strings.HasPrefix(raw, code) {
			// RFC 959 requires numeric-looking intermediate lines to be padded.
			if len(raw) >= 3 && raw[0] >= '0' && raw[0] <= '9' && raw[1] >= '0' && raw[1] <= '9' && raw[2] >= '0' && raw[2] <= '9' {
				return first
			}
			// Plain intermediate FTP text belongs to this reply, unchanged.
			if code == "220" {
				parts = append(parts, text)
				size += len(text) + 2
				if size > fingerprints.MaxInputBytes+2 {
					return first
				}
			}
			continue
		}
		if !strings.HasPrefix(raw, code) || len(raw) > 3 && raw[3] != ' ' && raw[3] != '-' {
			return first
		}
		if len(raw) == 3 {
			if service != "smtp" {
				return first
			}
			text, done = "", true
		} else {
			text, done = raw[4:], raw[3] == ' '
		}
		if code == "220" {
			parts = append(parts, text)
			size += len(text) + 2
			if size > fingerprints.MaxInputBytes+2 {
				return first
			}
		}
		if !done {
			continue
		}
		if code == "120" {
			code = ""
			continue
		}
		field := fingerprints.FTPBanner
		if service == "smtp" {
			field = fingerprints.SMTPBanner
		}
		return bannerObservation{Text: greetingText, Field: field, Value: strings.Join(parts, "\r\n")}
	}
	return first
}
