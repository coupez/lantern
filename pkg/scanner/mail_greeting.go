package scanner

import (
	"bufio"
	"io"
	"strings"

	"github.com/coupez/lantern/pkg/fingerprints"
)

// Only the first complete positive greeting is eligible. No capability, login,
// mailbox, or upgrade commands are sent. Response codes remain part of the text.
func observeMailGreeting(src io.Reader, service string) bannerObservation {
	limit := fingerprints.MaxInputBytes + len("* PREAUTH ") + 2
	if service == "pop3" {
		limit = 512
	}
	reader := bufio.NewReaderSize(io.LimitReader(src, int64(limit)), limit)
	line, err := reader.ReadSlice('\n')
	result := bannerObservation{Text: CleanText(strings.TrimSpace(string(line)))}
	if err != nil || !strings.HasSuffix(string(line), "\r\n") {
		return result
	}
	raw := string(line[:len(line)-2])
	if service == "pop3" {
		// RFC 1939 requires uppercase status indicators. Refusals are diagnostic only.
		if !strings.HasPrefix(raw, "+OK ") {
			return result
		}
		result.Field, result.Value = fingerprints.POP3Banner, raw[4:]
	} else {
		// IMAP atoms are case-insensitive; keep capability/response-code text intact.
		for _, prefix := range []string{"* OK ", "* PREAUTH "} {
			if len(raw) >= len(prefix) && strings.EqualFold(raw[:len(prefix)], prefix) {
				result.Field, result.Value = fingerprints.IMAPBanner, raw[len(prefix):]
				break
			}
		}
	}
	if len(result.Value) > fingerprints.MaxInputBytes {
		result.Field, result.Value = "", ""
	}
	return result
}
