package fingerbank

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func validAttributes() Attributes { return Attributes{DHCPFingerprint: "1,3,6,15"} }

func TestLookupRequestAndMatchedResponse(t *testing.T) {
	const key = "private-api-key"
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.String() != Endpoint || r.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", r.Method, r.URL)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+key {
			t.Fatalf("authorization = %q", got)
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
			t.Fatalf("headers = %#v", r.Header)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil || string(b) != `{"dhcp_fingerprint":"1,3,6,15"}` {
			t.Fatalf("body = %q, %v", b, err)
		}
		return response(200, `{"device":{"id":44,"name":"Phone","parent_id":2,"parents":[{"id":2,"name":"Mobile","parent_id":null}],"ignored":true},"device_name":"Mobile/Phone","score":88,"version":"1","request_id":"req","vulnerabilities":{"secret":"discarded"}}`), nil
	})
	got, err := lookup(context.Background(), key, validAttributes(), rt)
	if err != nil || got.Status != "matched" || got.Classification == nil || got.Classification.Device.ID != 44 || len(got.Classification.Device.Parents) != 1 {
		t.Fatalf("result = %#v, %v", got, err)
	}
}

func TestLookupUnknownAndHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{404, "unknown"}, {401, "error"}, {429, "error"}, {502, "error"}, {302, "error"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			got, err := lookup(context.Background(), "key", validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				r := response(tc.status, "untrusted private-api-key body")
				if tc.status == 302 {
					r.Header.Set("Location", "https://attacker.invalid/")
				}
				return r, nil
			}))
			if tc.want == "unknown" {
				if err != nil || got.Status != "unknown" || got.Classification != nil {
					t.Fatal(got, err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private-api-key") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestLookupRejectsInputBeforeNetwork(t *testing.T) {
	calls := 0
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(200, "{}"), nil })
	for _, key := range []string{"", "two words", "bad\nkey", strings.Repeat("x", 513)} {
		if _, err := lookup(context.Background(), key, validAttributes(), rt); err == nil {
			t.Fatalf("accepted key %q", key)
		}
	}
	if _, err := lookup(context.Background(), "key", Attributes{}, rt); err == nil {
		t.Fatal("accepted empty attributes")
	}
	if calls != 0 {
		t.Fatalf("network calls = %d", calls)
	}
}

func TestLookupTransportErrorsCancellationAndRedaction(t *testing.T) {
	secret := "private-api-key"
	_, err := lookup(context.Background(), secret, validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport reflected " + secret)
	}))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = lookup(ctx, secret, validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport called for canceled context")
		return nil, nil
	}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestLookupResponseFramingAndBounds(t *testing.T) {
	valid := `{"device":{"id":1,"name":"Device","parent_id":null,"parents":[]},"device_name":"Device","score":50,"version":"","request_id":""}`
	bad := []string{
		strings.Replace(valid, `"score":50`, `"score":50,"ſcore":99`, 1),
		`{"device":{"id":1,"name":"A","name":"B","parents":[]},"device_name":"A","score":1}`,
		`{"device":{"id":1,"name":"A","Name":"B","parents":[]},"device_name":"A","score":1,"version":"","request_id":""}`,
		valid + `{}`,
		`{"device":{"id":0,"name":"Device","parents":[]},"device_name":"Device","score":50}`,
		`{"device":{"id":1,"name":"Device","parents":[]},"device_name":"Device","score":101}`,
		`{"device":{"id":1,"name":"bad\u0000","parents":[]},"device_name":"Device","score":1}`,
		`{"device":{"id":1,"name":"Device","parents":[]},"device_name":"bad\ufffd","score":1}`,
		`{"device":{"id":1,"name":"Device","parents":[]},"device_name":"Device","version":"","request_id":""}`,
		`{"device":{"id":1,"name":"Device","parents":[]},"device_name":"Device","score":null,"version":"","request_id":""}`,
		`{"device":{"id":1,"name":"Device","parents":[{"id":1,"name":"self"}]},"device_name":"Device","score":1,"version":"","request_id":""}`,
	}
	for _, body := range bad {
		_, err := lookup(context.Background(), "key", validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, body), nil }))
		if err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	over := strings.Repeat(" ", maxResponse+1)
	if _, err := lookup(context.Background(), "key", validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, over), nil })); err == nil {
		t.Fatal("accepted oversized response")
	}
	deep := strings.TrimSuffix(valid, "}") + `,"ignored":` + strings.Repeat(`{"x":`, 34) + `0` + strings.Repeat("}", 34) + "}"
	if _, err := lookup(context.Background(), "key", validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, deep), nil })); err == nil {
		t.Fatal("accepted deeply nested response")
	}
	echo := strings.Replace(valid, `"request_id":""`, `"request_id":"private-key"`, 1)
	if _, err := lookup(context.Background(), "private-key", validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, echo), nil })); err == nil {
		t.Fatal("accepted response echoing API key")
	}
	escapedEcho := strings.Replace(valid, `"request_id":""`, `"request_id":"private\u002dkey"`, 1)
	if _, err := lookup(context.Background(), "private-key", validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, escapedEcho), nil })); err == nil {
		t.Fatal("accepted escaped response echoing API key")
	}
	invalidUTF8 := []byte(strings.Replace(valid, `"name":"Device"`, "\"name\":\"bad\xff\"", 1))
	if _, err := lookup(context.Background(), "key", validAttributes(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(invalidUTF8)))}, nil
	})); err == nil {
		t.Fatal("accepted invalid UTF-8 response")
	}
}

func TestLookupHonorsInFlightCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	done := make(chan error, 1)
	go func() { _, err := lookup(ctx, "key", validAttributes(), rt); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop request")
	}
}
