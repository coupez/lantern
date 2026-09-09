package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/coupez/lantern/pkg/fingerbank"
	"github.com/coupez/lantern/pkg/observe"
)

type fingerbankInput struct {
	Summary      observe.Summary       `json:"summary"`
	Observations []observe.Observation `json:"observations"`
}

type fingerbankRow struct {
	Packet        int                    `json:"packet"`
	Timestamp     time.Time              `json:"timestamp"`
	Section       uint32                 `json:"section"`
	Interface     uint32                 `json:"interface"`
	LinkType      uint16                 `json:"link_type"`
	Version       int                    `json:"dhcp_version"`
	Type          uint8                  `json:"dhcp_type"`
	Eligible      bool                   `json:"eligible"`
	Reason        string                 `json:"reason,omitempty"`
	Payload       *fingerbank.Attributes `json:"payload,omitempty"`
	PayloadSHA256 string                 `json:"payload_sha256,omitempty"`
	Provider      *fingerbank.Result     `json:"provider,omitempty"`
}

type fingerbankOutput struct {
	Schema           int             `json:"schema"`
	Mode             string          `json:"mode"`
	Endpoint         string          `json:"endpoint"`
	Notice           string          `json:"notice"`
	SourceSHA256     string          `json:"source_sha256"`
	SourceIncomplete bool            `json:"source_incomplete"`
	SubmittedAt      *time.Time      `json:"submitted_at,omitempty"`
	Rows             []fingerbankRow `json:"observations"`
	Error            string          `json:"error,omitempty"`
}

type fingerbankLookup func(context.Context, string, fingerbank.Attributes) (fingerbank.Result, error)

// Preview is entirely local. A submission selects exactly one packet, preserving
// packet provenance without asserting that the packet identifies a unique device.
func fingerbankCommand(ctx context.Context, args []string, out io.Writer, lookupEnv func(string) (string, bool), lookup fingerbankLookup) error {
	f := flag.NewFlagSet("fingerbank", flag.ContinueOnError)
	f.SetOutput(out)
	file := f.String("read", "", "saved observe --json file (maximum 17 MiB)")
	packet := f.Int("packet", 0, "capture packet number; required for submission")
	submit := f.Bool("submit", false, "send the selected payload to Fingerbank Cloud; unknown combinations may be added to its database")
	keyEnv := f.String("key-env", "", "environment variable containing the Fingerbank API key; required with --submit")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *file == "" || f.NArg() != 0 || *packet < 0 || (*submit && (*packet == 0 || *keyEnv == "")) || (!*submit && *keyEnv != "") {
		return errors.New("usage: lantern fingerbank --read OBSERVE.json [--packet N] [--submit --key-env NAME]")
	}
	if len(*keyEnv) > 128 {
		return errors.New("invalid key-env name")
	}
	for i, r := range *keyEnv {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return errors.New("invalid key-env name")
		}
	}
	var input fingerbankInput
	hash, err := readBoundedJSON(*file, &input, true, 17<<20)
	if err != nil {
		return err
	}
	if input.Summary.Schema != 1 || len(input.Observations) > 5000 || input.Summary.Observations != len(input.Observations) || input.Summary.Capture.Packets < len(input.Observations) || input.Summary.Capture.Packets > 1000000 {
		return errors.New("invalid observation summary or more than 5000 observations")
	}
	result := fingerbankOutput{Schema: 1, Mode: "preview", Endpoint: fingerbank.Endpoint, SourceSHA256: hash,
		SourceIncomplete: input.Summary.Incomplete || input.Summary.Error != "" || input.Summary.Malformed > 0 || input.Summary.Truncated > 0 || input.Summary.Unsupported > 0,
		Notice:           "Submission sends only the displayed payload and API authorization to Fingerbank Cloud. Unknown combinations may be added to its database. Provider scores and classifications are not measured hardware identity.", Rows: []fingerbankRow{}}
	previous := 0
	for _, o := range input.Observations {
		if o.Packet <= previous || o.Packet > input.Summary.Capture.Packets {
			return errors.New("observation packet numbers must increase within capture bounds")
		}
		previous = o.Packet
		if *packet != 0 && o.Packet != *packet {
			continue
		}
		row := fingerbankRow{Packet: o.Packet, Timestamp: o.Timestamp, Section: o.Section, Interface: o.Interface, LinkType: o.LinkType, Version: o.Message.Version, Type: o.Message.Type}
		a, e := fingerbank.Extract(o)
		if e != nil {
			row.Reason = e.Error()
		} else {
			row.Eligible, row.Payload = true, &a
			b, _ := json.Marshal(a)
			h := sha256.Sum256(b)
			row.PayloadSHA256 = hex.EncodeToString(h[:])
		}
		result.Rows = append(result.Rows, row)
	}
	if *packet != 0 && len(result.Rows) != 1 {
		return errors.New("selected packet is absent from the observation file")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var lookupErr error
	if *submit {
		if !result.Rows[0].Eligible {
			return errors.New("selected packet is ineligible; preview it without --submit for the reason")
		}
		key, ok := lookupEnv(*keyEnv)
		if !ok || key == "" {
			return errors.New("the configured Fingerbank API key environment variable is unset or empty")
		}
		result.Mode = "submitted"
		now := time.Now().UTC()
		result.SubmittedAt = &now
		provider, e := lookup(ctx, key, *result.Rows[0].Payload)
		if e != nil {
			// The client returns credential-free errors; never expose arbitrary
			// injected requester errors through the report or terminal.
			lookupErr = errors.New("Fingerbank lookup failed; no classification was accepted")
			var status *fingerbank.HTTPError
			if errors.As(e, &status) {
				lookupErr = fmt.Errorf("Fingerbank returned HTTP %d; no classification was accepted", status.StatusCode)
			} else if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				lookupErr = ctx.Err()
				if lookupErr == nil {
					lookupErr = context.DeadlineExceeded
				}
			}
			result.Error = lookupErr.Error()
		} else {
			result.Rows[0].Provider = &provider
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}
	return lookupErr
}
