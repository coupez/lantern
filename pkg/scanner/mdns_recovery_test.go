package scanner

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestMDNSRetryFailurePreservesPartialResults(t *testing.T) {
	c := multicastErrorFixture(t, "mDNS", 0)
	c.waitDeadline = true
	c.failWrite, c.writeErr = len(mdnsKinds)+1, io.ErrClosedPipe
	start := time.Now()
	hits, err := collectMDNS(context.Background(), c, c.peer, netip.MustParsePrefix("192.0.2.0/24"), start.Add(3*time.Second))
	if len(hits) != 1 || !errors.Is(err, io.ErrClosedPipe) || !strings.Contains(err.Error(), "retry") || c.writes != len(mdnsKinds)+1 || time.Since(start) > 2*time.Second {
		t.Fatal(hits, err, c.writes, time.Since(start))
	}
}

func TestMDNSReadDeadlineFailureAndExpiredDeadline(t *testing.T) {
	c := multicastErrorFixture(t, "mDNS", 0)
	c.beforeRead = func(int) { c.deadlineErr = io.ErrClosedPipe }
	hits, err := collectMDNS(context.Background(), c, c.peer, netip.MustParsePrefix("192.0.2.0/24"), time.Now().Add(3*time.Second))
	if len(hits) != 1 || !errors.Is(err, io.ErrClosedPipe) || !strings.Contains(err.Error(), "read deadline") {
		t.Fatal(hits, err)
	}
	c = multicastErrorFixture(t, "mDNS", 0)
	hits, err = collectMDNS(context.Background(), c, c.peer, netip.MustParsePrefix("192.0.2.0/24"), time.Now().Add(-time.Second))
	if len(hits) != 0 || err != nil || c.writes != 0 || c.reads != 0 {
		t.Fatal("expired window performed I/O", hits, err, c.writes, c.reads)
	}
}

func TestMDNSShortWindowDoesNotRetry(t *testing.T) {
	c := multicastErrorFixture(t, "mDNS", 0)
	c.waitDeadline = true
	hits, err := collectMDNS(context.Background(), c, c.peer, netip.MustParsePrefix("192.0.2.0/24"), time.Now().Add(20*time.Millisecond))
	if len(hits) != 1 || err != nil || c.writes != len(mdnsKinds) {
		t.Fatal(hits, err, c.writes)
	}
}

func TestMDNSRetriesShareQueryBudget(t *testing.T) {
	c := multicastErrorFixture(t, "mDNS", 30)
	c.waitDeadline = true
	hits, err := collectMDNS(context.Background(), c, c.peer, netip.MustParsePrefix("192.0.2.0/24"), time.Now().Add(1100*time.Millisecond))
	if len(hits) != 1 || err == nil || !strings.Contains(err.Error(), "query limit reached") || c.writes != maxMDNSQueries {
		t.Fatal("retries escaped shared budget", hits, err, c.writes)
	}
}

func TestMDNSAnsweredQuestionFamilies(t *testing.T) {
	r := newMDNSRecords()
	name := "fixture.local."
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("FIXTURE.local."), Class: dnsmessage.ClassINET}
	r.addresses[name] = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	q.Type = dnsmessage.TypeA
	if !r.answered(q) {
		t.Fatal("IPv4 address not recognized")
	}
	q.Type = dnsmessage.TypeAAAA
	if r.answered(q) {
		t.Fatal("IPv4 answer suppressed IPv6 retry")
	}
	r.addresses[name] = []netip.Addr{netip.MustParseAddr("::"), netip.MustParseAddr("ff02::1")}
	if r.answered(q) {
		t.Fatal("non-host address suppressed retry")
	}
	r.addresses[name] = append(r.addresses[name], netip.MustParseAddr("2001:db8::1"))
	if !r.answered(q) {
		t.Fatal("IPv6 address not recognized")
	}
	q.Type = dnsmessage.TypeTXT
	if r.answered(q) {
		t.Fatal("missing TXT suppressed retry")
	}
	r.txt[name] = map[string]string{}
	if !r.answered(q) {
		t.Fatal("empty TXT should count as an answer")
	}
	q.Type = dnsmessage.TypeSRV
	if r.answered(q) {
		t.Fatal("missing SRV suppressed retry")
	}
	r.services[name] = dnsmessage.SRVResource{}
	if !r.answered(q) {
		t.Fatal("SRV answer not recognized")
	}
	q.Type = dnsmessage.TypePTR
	if r.answered(q) {
		t.Fatal("missing PTR suppressed retry")
	}
	r.pointers[name] = []string{"instance.local."}
	if !r.answered(q) {
		t.Fatal("PTR answer not recognized")
	}
}
