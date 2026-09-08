package ui

import (
	"context"
	"errors"
	"fmt"
	"github.com/coupez/lantern/pkg/scanner"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

// WatchOptions connects the terminal view to a cancellable scan, without giving
// the discovery engine any dependency on a terminal or the CLI.
type WatchOptions struct {
	Target, Profile  string
	Interval         time.Duration
	NoColor, Details bool
	Scan             func(context.Context, func(scanner.Event)) (scanner.Report, error)
	Complete         func(scanner.Report) error
}

func CanWatch(in, out *os.File) bool {
	return terminalInputSupported && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(out.Fd()))
}

type scanResult struct {
	report scanner.Report
	err    error
}

// The mailbox coalesces progress and discovery events. A slow terminal never
// blocks network probes; the completed report remains the authoritative result.
type watchMailbox struct {
	sync.Mutex
	completed, total int
	phase            string
	discovered       map[string]scanner.Device
}

func (b *watchMailbox) emit(e scanner.Event) {
	b.Lock()
	defer b.Unlock()
	if e.Type == "progress" || e.Type == "device_update" {
		b.completed, b.total, b.phase = e.Completed, e.Total, e.Phase
	}
	if (e.Type == "device" || e.Type == "device_update") && e.Device != nil {
		// Also isolate custom WatchOptions.Scan implementations from UI ownership.
		d := e.Device.Clone()
		b.discovered[d.IP.String()] = d
	}
}
func (b *watchMailbox) update(m *watchModel) {
	b.Lock()
	defer b.Unlock()
	m.completed, m.total, m.phase = b.completed, b.total, b.phase
	m.discovered = len(b.discovered)
	if !m.hasReport {
		m.report.Devices = m.report.Devices[:0]
		for _, d := range b.discovered {
			m.report.Devices = append(m.report.Devices, d)
		}
	}
}

// RunWatch restores terminal state on every normal exit, cancellation, and error.
// Scan must honor its context. Workers finish before the terminal is restored.
func RunWatch(ctx context.Context, in, out *os.File, o WatchOptions) (err error) {
	if !CanWatch(in, out) {
		return errors.New("interactive watch requires a terminal; use watch --plain")
	}
	if o.Scan == nil || o.Interval <= 0 {
		return errors.New("watch requires a scan and a positive interval")
	}
	u := New(out, o.NoColor)
	state, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return err
	}
	defer func() {
		reset := ""
		if u.Color {
			reset = "\x1b[0m"
		}
		_, displayErr := io.WriteString(out, reset+"\x1b[?2004l\x1b[?25h\x1b[?1049l")
		restoreErr := term.Restore(int(in.Fd()), state)
		err = errors.Join(err, displayErr, restoreErr)
	}()
	if _, err = io.WriteString(out, "\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[2J"); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	keys := make(chan string, 32)
	inputDone := make(chan error, 1)
	go func() { inputDone <- readWatchKeys(ctx, in, keys) }()
	defer func() { cancel(); err = errors.Join(err, <-inputDone) }()
	results := make(chan scanResult, 1)
	m := watchModel{target: o.Target, profile: o.Profile, details: o.Details}
	var mailbox *watchMailbox
	finish := func(r scanResult) error {
		m.scanning = false
		if r.err != nil && r.report.Error == "" {
			return r.err
		}
		if o.Complete != nil {
			if e := o.Complete(r.report); e != nil {
				return errors.Join(r.err, e)
			}
		}
		if r.err != nil {
			return r.err
		}
		m.accept(r.report)
		m.next = time.Now().Add(o.Interval)
		return nil
	}
	start := func() {
		m.scanning = true
		m.started = time.Now()
		m.completed = 0
		m.phase = ""
		m.total = 0
		m.discovered = 0
		mailbox = &watchMailbox{discovered: make(map[string]scanner.Device)}
		go func(b *watchMailbox) { r, e := o.Scan(ctx, b.emit); results <- scanResult{r, e} }(mailbox)
	}
	// Cancellation also joins an in-flight scan and saves its partial snapshot.
	defer func() {
		cancel()
		if m.scanning {
			err = errors.Join(err, finish(<-results))
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	lastFrame := ""
	draw := func() error {
		if m.scanning {
			mailbox.update(&m)
		}
		w, h, e := term.GetSize(int(out.Fd()))
		if e != nil {
			return e
		}
		frame := m.frame(u, w, h, time.Now())
		if frame == lastFrame {
			return nil
		}
		if _, e = io.WriteString(out, frame); e != nil {
			return e
		}
		lastFrame = frame
		return nil
	}
	start()
	if err = draw(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case key, ok := <-keys:
			if !ok {
				return nil
			}
			action := m.key(key)
			if action == "quit" {
				return nil
			}
			if action == "refresh" && !m.scanning {
				start()
			}
		case r := <-results:
			if err = finish(r); err != nil {
				return err
			}
		case <-ticker.C:
			if !m.scanning && !m.paused && !time.Now().Before(m.next) {
				start()
			}
		}
		if err = draw(); err != nil {
			return err
		}
	}
}

func watchStatus(m *watchModel, now time.Time) string {
	if m.scanning {
		progress := "discovering"
		if m.total > 0 {
			label := "probing"
			if m.phase == "enrichment" {
				label = "identifying"
			}
			progress = fmt.Sprintf("%s %d%%", label, min(100, m.completed*100/m.total))
		}
		pause := ""
		if m.paused {
			pause = " · pauses after scan"
		}
		return fmt.Sprintf("SCANNING · %s · %d found · %.1fs%s", progress, m.discovered, now.Sub(m.started).Seconds(), pause)
	}
	if m.paused {
		return "PAUSED · r scans once · space resumes"
	}
	return fmt.Sprintf("WATCHING · refresh in %ds · last scan %.2fs", max(0, int(m.next.Sub(now).Seconds()+1)), float64(m.report.DurationMS)/1000)
}
