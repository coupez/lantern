package scanner

import (
	"context"
	"errors"
	"io"
	"testing"
)

type diagnosticCloser struct {
	closes int
	err    error
}

func (c *diagnosticCloser) Close() error { c.closes++; return c.err }

func TestDiagnosticFailureIsolationAndResourceCleanup(t *testing.T) {
	c := &diagnosticCloser{}
	r := Diagnostics{}
	runDiagnosticTasks(context.Background(), &r, []diagnosticTask{
		{"denied", "fallback", func(context.Context) (string, error) { return "", errors.New("permission denied") }},
		{"socket", "should disappear", func(context.Context) (string, error) {
			return "opened and closed", checkLocalSocket(func() (io.Closer, error) { return c, nil })
		}},
	})
	if len(r.Checks) != 2 || r.Checks[0].Status != "unavailable" || r.Checks[0].Hint != "fallback" || r.Checks[1].Status != "available" || r.Checks[1].Hint != "" || c.closes != 1 {
		t.Fatal(r, c.closes)
	}
	c = &diagnosticCloser{err: errors.New("close failed")}
	if err := checkLocalSocket(func() (io.Closer, error) { return c, nil }); err != c.err || c.closes != 1 {
		t.Fatal(err, c.closes)
	}
	denied := errors.New("open failed")
	if err := checkLocalSocket(func() (io.Closer, error) { return nil, denied }); err != denied {
		t.Fatal(err)
	}
}

func TestDiagnosticCancellationSkipsRemainingWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := Diagnostics{}
	runDiagnosticTasks(ctx, &r, []diagnosticTask{
		{"first", "", func(context.Context) (string, error) { return "done", nil }},
		{"cancelled", "", func(context.Context) (string, error) { cancel(); return "", ctx.Err() }},
		{"later", "", func(context.Context) (string, error) { t.Fatal("work started after cancellation"); return "", nil }},
	})
	if !r.Cancelled || len(r.Checks) != 3 || r.Checks[0].Status != "available" || r.Checks[1].Status != "not_checked" || r.Checks[2].Status != "not_checked" {
		t.Fatal(r)
	}
	report, err := Diagnose(ctx, "")
	if !errors.Is(err, context.Canceled) || !report.Cancelled || len(report.Checks) != 0 {
		t.Fatal(report, err)
	}
}
