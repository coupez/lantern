package vendors

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	if Count() < 58000 {
		t.Fatal(Count())
	}
	v, e := Lookup("00:00:0c:12:34:56")
	if e != nil || !strings.Contains(strings.ToLower(v.Name), "cisco") {
		t.Fatal(v, e)
	}
	v, e = Lookup("02:00:0c:12:34:56")
	if e != nil || !v.Private || v.Name != "" {
		t.Fatal(v, e)
	}
	v, e = Lookup("01:00:5e:00:00:01")
	if e != nil || !v.Multicast || v.Name != "" {
		t.Fatal(v, e)
	}
	if _, e = Lookup("garbage"); e == nil {
		t.Fatal("invalid MAC accepted")
	}
}
func TestLongestPrefix(t *testing.T) {
	Count()
	for prefix, want := range index {
		if len(prefix) != 9 {
			continue
		}
		raw := prefix + "000"
		mac := ""
		for i := 0; i < 12; i += 2 {
			if i > 0 {
				mac += ":"
			}
			mac += raw[i : i+2]
		}
		got, e := Lookup(mac)
		if got.Private || got.Multicast {
			continue
		}
		if e != nil || got != want {
			t.Fatal(prefix, got, want, e)
		}
		return
	}
	t.Fatal("no /36 record found")
}
func BenchmarkLookup(b *testing.B) {
	Count()
	b.ResetTimer()
	for range b.N {
		Lookup("00:00:0c:12:34:56")
	}
}
