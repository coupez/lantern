package fingerbank

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const Endpoint = "https://api.fingerbank.org/api/v2/combinations/interrogate"

const maxResponse = 128 << 10

type Device struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	ParentID *int     `json:"parent_id"`
	Parents  []Device `json:"parents"`
}

type Classification struct {
	Device     Device `json:"device"`
	DeviceName string `json:"device_name"`
	Score      int    `json:"score"`
	Version    string `json:"version"`
	RequestID  string `json:"request_id"`
}

type Result struct {
	Status         string          `json:"status"`
	Classification *Classification `json:"classification,omitempty"`
}

// HTTPError reports a non-success status without retaining response content.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Fingerbank request returned HTTP %d", e.StatusCode)
}

func Lookup(ctx context.Context, key string, a Attributes) (Result, error) {
	t := defaultTransport()
	defer t.CloseIdleConnections()
	return lookup(ctx, key, a, t)
}

func defaultTransport() *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 32 << 10,
	}
}

func lookup(ctx context.Context, key string, a Attributes, rt http.RoundTripper) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !validKey(key) {
		return Result{}, errors.New("invalid Fingerbank API key")
	}
	if err := a.Validate(); err != nil {
		return Result{}, err
	}
	body, err := json.Marshal(a)
	if err != nil {
		return Result{}, errors.New("invalid Fingerbank attributes")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, Endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, errors.New("cannot build Fingerbank request")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		if requestCtx.Err() != nil {
			return Result{}, requestCtx.Err()
		}
		return Result{}, errors.New("Fingerbank request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Result{Status: "unknown"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, &HTTPError{StatusCode: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return Result{}, errors.New("cannot read Fingerbank response")
	}
	if len(b) > maxResponse {
		return Result{}, errors.New("Fingerbank response exceeds limit")
	}
	if !utf8.Valid(b) || bytes.Contains(b, []byte(key)) {
		return Result{}, errors.New("invalid Fingerbank response")
	}
	if err := rejectDuplicateJSON(b); err != nil {
		return Result{}, errors.New("invalid Fingerbank response")
	}
	var required struct {
		Device     json.RawMessage `json:"device"`
		DeviceName *string         `json:"device_name"`
		Score      *int            `json:"score"`
	}
	if err := json.Unmarshal(b, &required); err != nil || len(required.Device) == 0 || string(required.Device) == "null" || required.DeviceName == nil || required.Score == nil {
		return Result{}, errors.New("invalid Fingerbank response")
	}
	var c Classification
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&c); err != nil {
		return Result{}, errors.New("invalid Fingerbank response")
	}
	if classificationContains(c, key) {
		return Result{}, errors.New("invalid Fingerbank response")
	}
	if err := validateClassification(c); err != nil {
		return Result{}, err
	}
	return Result{Status: "matched", Classification: &c}, nil
}

func classificationContains(c Classification, text string) bool {
	if strings.Contains(c.Device.Name, text) || strings.Contains(c.DeviceName, text) || strings.Contains(c.Version, text) || strings.Contains(c.RequestID, text) {
		return true
	}
	for _, p := range c.Device.Parents {
		if strings.Contains(p.Name, text) {
			return true
		}
	}
	return false
}

func validKey(s string) bool {
	if len(s) == 0 || len(s) > 512 {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func validResponseText(s string, max int, empty bool) bool {
	if len(s) > max || (!empty && len(s) == 0) || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func validateClassification(c Classification) error {
	if c.Device.ID <= 0 || c.Device.ParentID != nil && (*c.Device.ParentID < 0 || *c.Device.ParentID == c.Device.ID) || !validResponseText(c.Device.Name, 1024, false) || len(c.Device.Parents) > 64 || c.Score < 0 || c.Score > 100 || !validResponseText(c.DeviceName, 4096, false) || !validResponseText(c.Version, 1024, true) || !validResponseText(c.RequestID, 1024, true) {
		return errors.New("invalid Fingerbank classification")
	}
	ids := map[int]bool{c.Device.ID: true}
	for _, p := range c.Device.Parents {
		if p.ID <= 0 || ids[p.ID] || p.ParentID != nil && (*p.ParentID < 0 || *p.ParentID == p.ID) || !validResponseText(p.Name, 1024, false) || len(p.Parents) != 0 {
			return errors.New("invalid Fingerbank device hierarchy")
		}
		ids[p.ID] = true
	}
	return nil
}

func rejectDuplicateJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting exceeds limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				folded := foldJSONKey(key)
				if !ok || seen[folded] {
					return errors.New("duplicate JSON member")
				}
				seen[folded] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

// encoding/json uses Unicode simple folding as well as ASCII case matching.
// Lowercasing alone misses aliases such as the long s in "ſcore".
func foldJSONKey(s string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < min {
				min = next
			}
		}
		return min
	}, s)
}
