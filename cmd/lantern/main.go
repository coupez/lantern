package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/coupez/lantern/internal/ui"
	"github.com/coupez/lantern/pkg/android"
	"github.com/coupez/lantern/pkg/fingerbank"
	"github.com/coupez/lantern/pkg/fingerprints"
	"github.com/coupez/lantern/pkg/models"
	"github.com/coupez/lantern/pkg/scanner"
	"github.com/coupez/lantern/pkg/snmp"
	"github.com/coupez/lantern/pkg/vendors"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Set by release builds; go install uses the module version when unset.
var version string

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lantern:", scanner.CleanText(err.Error()))
		os.Exit(1)
	}
}
func run(args []string) error {
	cmd := "scan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if _, _, err := scanner.ParseTargetSpec(args[0]); err != nil {
			cmd = args[0]
			args = args[1:]
		}
	}
	switch cmd {
	case "help":
		help()
		return nil
	case "version":
		fmt.Println("lantern", buildVersion())
		return nil
	case "enrich":
		return enrichCommand(args, os.Stdout)
	case "evaluate":
		return evaluateCommand(args, os.Stdout)
	case "fingerbank":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return fingerbankCommand(ctx, args, os.Stdout, os.LookupEnv, fingerbank.Lookup)
	case "android":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return androidCommand(ctx, args, os.Stdout, android.Read)
	case "snmp":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return snmpCommand(ctx, args, os.Stdout, os.LookupEnv, snmp.Read)
	case "observe":
		return observeCommand(args)
	case "interfaces":
		n, err := scanner.Networks()
		if err != nil {
			return err
		}
		n6, _ := scanner.Networks6()
		n = append(n, n6...)
		for _, v := range n {
			fmt.Printf("%-12s %-39s %s\n", v.Interface, v.CIDR, v.MAC)
		}
		return nil
	case "fingerprint":
		if len(args) == 0 {
			fmt.Printf("%d offline SSH/HTTP/FTP/SMTP/IMAP/POP3 banner patterns · Rapid7 Recog catalog claims\n", fingerprints.Count())
			return nil
		}
		if len(args) == 1 && args[0] == "sources" {
			fmt.Print(fingerprints.Sources)
			return nil
		}
		if len(args) != 2 || (args[0] != "ssh" && args[0] != "http" && args[0] != "ftp" && args[0] != "smtp" && args[0] != "imap" && args[0] != "pop3") {
			return errors.New("usage: lantern fingerprint [ssh SOFTWARE_AND_COMMENTS | http SERVER_HEADER | ftp GREETING_TEXT | smtp GREETING_TEXT | imap GREETING_TEXT | pop3 GREETING_TEXT | sources]")
		}
		field := fingerprints.HTTPServer
		if args[0] == "ssh" {
			field = fingerprints.SSHBanner
		} else if args[0] == "ftp" {
			field = fingerprints.FTPBanner
		} else if args[0] == "smtp" {
			field = fingerprints.SMTPBanner
		} else if args[0] == "imap" {
			field = fingerprints.IMAPBanner
		} else if args[0] == "pop3" {
			field = fingerprints.POP3Banner
		}
		return json.NewEncoder(os.Stdout).Encode(fingerprints.Lookup(field, args[1]))
	case "models":
		if len(args) == 0 {
			fmt.Printf("%d offline AppleDB/Shelly hardware identifiers · exact matches with all candidates\n", models.Count())
			return nil
		}
		if len(args) != 1 {
			return errors.New("usage: lantern models [IDENTIFIER | sources]")
		}
		if args[0] == "sources" {
			return json.NewEncoder(os.Stdout).Encode(models.Sources())
		}
		return json.NewEncoder(os.Stdout).Encode(models.Lookup(args[0]))
	case "vendors":
		if len(args) > 0 && args[0] == "sources" {
			fmt.Print(vendors.Sources)
		} else {
			fmt.Printf("%s\n", fmt.Sprintf("%d offline IEEE assignments · MA-L / MA-M / MA-S / IAB", vendors.Count()))
		}
		return nil
	case "lookup":
		if len(args) != 1 {
			return errors.New("usage: lantern lookup MAC")
		}
		v, err := vendors.Lookup(args[0])
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(v)
	case "diff":
		if len(args) != 2 {
			return errors.New("usage: lantern diff BEFORE.json AFTER.json")
		}
		a, err := scanner.Load(args[0])
		if err != nil {
			return err
		}
		b, err := scanner.Load(args[1])
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(scanner.Diff(a, b))
	case "doctor":
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return doctorCommand(ctx, args, os.Stdout, scanner.Diagnose)
	case "wake":
		return wake(args)
	case "demo":
		return demoCommand(args)
	case "inspect":
		return scan(append([]string{"--profile", "deep", "--details"}, args...), false)
	case "scan", "watch":
		return scan(args, cmd == "watch")
	default:
		return fmt.Errorf("unknown command %q; run lantern help", cmd)
	}
}
func help() {
	io.WriteString(os.Stdout, `
  ◈ LANTERN  ·  See your network clearly.

  lantern                         Discover your local network
  lantern scan [CIDR | IP]        Scan a network or single host
  lantern inspect IP              Detailed device and service inspection
  lantern watch [CIDR]            Live dashboard and network changes
  lantern observe --read FILE    Import DHCP evidence from PCAP/PCAPNG offline
  lantern fingerbank --read FILE Preview optional cloud DHCP classification
  lantern enrich --scan FILE --inventory FILE  Attach explicitly bound inventory
  lantern evaluate --truth FILE  Score saved observations against device labels
  lantern snmp IP --community-env NAME  Read configured SNMP device inventory
  lantern android --transport-id ID    Read owner-authorized Android inventory
  lantern interfaces              List available IPv4/IPv6 networks
  lantern lookup MAC              Identify a MAC vendor offline
  lantern fingerprint [TYPE TEXT] Offline service recognition
                                  TYPE: ssh, http, ftp, smtp, imap, pop3; or sources
  lantern models [IDENTIFIER]     Look up hardware model candidates offline
  lantern vendors [sources]       Database size and provenance
  lantern diff before.json after.json
  lantern wake MAC [broadcast-IP] Send a Wake-on-LAN packet
  lantern doctor [--json]         Check local capabilities without sending probes
  lantern demo [--watch]          Preview with synthetic data; no network use

  Scan options
    --profile quick|standard|deep  Default: standard
    --ports 22,80,443,8000-8100     Custom TCP ports (or none)
    --timeout 300ms                Per-probe deadline
    --concurrency 512              Maximum concurrent TCP probes
    --interface en0                Select local network / IPv6 zone
    --ipv6                         Discover local IPv6 neighbors
    --arp                          Direct IPv4 ARP (needs raw link access)
    --ndp                          Direct IPv6 NDP (needs raw link access)
    --netbios                      IPv4 NetBIOS names (deep default)
    --json | --jsonl | --csv        Structured output
    --save scan.json               Save a snapshot atomically
    --no-dns | --no-icmp            Disable discovery components
    --no-multicast                  Skip mDNS, SSDP, WS-Discovery (quick default)
    --no-descriptions               Skip UPnP/Shelly/Roku/IPP/ONVIF identity reads
    --details                      Show full device records
    --banners                      Read SSH/HTTP/HTTPS/service banners
    --all-hosts                    Scan ports even on silent hosts
    --plain                        Append watch reports without a dashboard
    --interval 10s                 Delay between watch scans
    --max-hosts 4096               Maximum target addresses
    --no-color                     Disable colors (also NO_COLOR)

  Examples
    lantern scan --ipv6 --interface en0
    lantern scan fe80::1%en0
    lantern scan --profile quick
    lantern 192.168.1.0/24 --json > network.json
    lantern scan 192.168.1.42 --ports 1-65535 --banners
    lantern watch --save latest.json

`)
}

// Move positionals behind flags so both `scan CIDR --json` and `scan --json CIDR` work.
func reorder(args []string) []string {
	value := map[string]bool{"profile": true, "ports": true, "timeout": true, "concurrency": true, "interface": true, "save": true, "interval": true, "max-hosts": true, "community-env": true, "port": true}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		s := args[i]
		if strings.HasPrefix(s, "-") {
			flags = append(flags, s)
			key := strings.TrimLeft(s, "-")
			if !strings.Contains(key, "=") && value[key] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, s)
		}
	}
	return append(flags, pos...)
}
func scan(args []string, watch bool) error {
	o := scanner.Defaults()
	f := flag.NewFlagSet("scan", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	profile := f.String("profile", "standard", "")
	ports := f.String("ports", "", "")
	iface := f.String("interface", "", "")
	save := f.String("save", "", "")
	asJSON := f.Bool("json", false, "")
	asJSONL := f.Bool("jsonl", false, "")
	asCSV := f.Bool("csv", false, "")
	noColor := f.Bool("no-color", false, "")
	plain := f.Bool("plain", false, "append watch reports without a dashboard")
	details := f.Bool("details", false, "")
	noDNS := f.Bool("no-dns", false, "")
	ipv6 := f.Bool("ipv6", false, "discover IPv6 neighbors on the selected interface")
	noICMP := f.Bool("no-icmp", false, "")
	noMulticast := f.Bool("no-multicast", false, "")
	noDescriptions := f.Bool("no-descriptions", false, "")
	interval := f.Duration("interval", 10*time.Second, "")
	f.DurationVar(&o.Timeout, "timeout", o.Timeout, "")
	f.IntVar(&o.Concurrency, "concurrency", o.Concurrency, "")
	f.IntVar(&o.MaxHosts, "max-hosts", o.MaxHosts, "")
	f.BoolVar(&o.Banners, "banners", false, "")
	f.BoolVar(&o.NetBIOS, "netbios", false, "unicast IPv4 NetBIOS node-status discovery")
	f.BoolVar(&o.NDP, "ndp", false, "direct IPv6 neighbor solicitation (requires raw link access)")
	f.BoolVar(&o.ARP, "arp", false, "direct IPv4 ARP discovery (requires raw link access)")
	f.BoolVar(&o.AllHosts, "all-hosts", false, "scan ports even without discovery responses")
	f.Usage = help
	if err := f.Parse(reorder(args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if f.NArg() > 1 {
		return errors.New("specify one IP address or CIDR")
	}
	formats := 0
	for _, b := range []bool{*asJSON, *asJSONL, *asCSV} {
		if b {
			formats++
		}
	}
	if formats > 1 {
		return errors.New("choose one of --json, --jsonl, or --csv")
	}
	if watch && *asJSON {
		return errors.New("use --jsonl for watch output")
	}
	if watch && *asCSV {
		return errors.New("use --jsonl for watch output")
	}
	if watch && *interval < time.Second {
		return errors.New("watch interval must be at least 1s")
	}
	explicit := map[string]bool{}
	f.Visit(func(flag *flag.Flag) { explicit[flag.Name] = true })
	switch *profile {
	case "quick":
		if !explicit["no-multicast"] {
			*noMulticast = true
		}
		if !explicit["no-descriptions"] {
			*noDescriptions = true
		}
		o.Ports = []uint16{80, 443}
	case "standard":
	case "deep":
		o.Ports, _ = scanner.ParsePorts("21-23,25,53,80,110,139,143,443,445,554,631,1883,3000,3306,3389,5000,5432,5900,6379,7000,8008-8009,8080,8443,9000,9100")
		if !explicit["banners"] {
			o.Banners = true
		}
	default:
		return errors.New("profile must be quick, standard, or deep")
	}
	var err error
	if *ports != "" {
		o.Ports, err = scanner.ParsePorts(*ports)
		if err != nil {
			return err
		}
	}
	o.Interface = *iface
	if f.NArg() == 1 {
		var zone string
		o.Target, zone, err = scanner.ParseTargetSpec(f.Arg(0))
		if zone != "" {
			if o.Interface != "" && o.Interface != zone {
				return errors.New("target zone and --interface disagree")
			}
			o.Interface = zone
		}
		if err == nil && *ipv6 && !o.Target.Addr().Is6() {
			return errors.New("--ipv6 requires an IPv6 target")
		}
	} else if *ipv6 {
		o.Target, o.Interface, err = scanner.AutoTarget6(*iface)
	} else {
		o.Target, o.Interface, err = scanner.AutoTarget4(*iface)
	}
	if err != nil {
		return err
	}
	if *profile == "deep" && !explicit["netbios"] && o.Target.Addr().Is4() {
		o.NetBIOS = true
	}
	o.Resolve = !*noDNS
	o.ICMP = !*noICMP
	o.Multicast = !*noMulticast
	o.Descriptions = !*noDescriptions
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *asJSONL {
		// Return EPIPE so streaming scans can cancel, join workers, and save.
		signal.Ignore(syscall.SIGPIPE)
		defer signal.Reset(syscall.SIGPIPE)
	}
	u := ui.New(os.Stderr, *noColor)
	human := formats == 0
	if watch && human && !*plain && ui.CanWatch(os.Stdin, os.Stdout) {
		label := o.Target.String()
		if o.Interface != "" {
			label += " on " + o.Interface
		}
		return ui.RunWatch(ctx, os.Stdin, os.Stdout, ui.WatchOptions{
			Target: label, Profile: *profile, Interval: *interval, NoColor: *noColor, Details: *details,
			Scan: func(ctx context.Context, emit func(scanner.Event)) (scanner.Report, error) {
				return (scanner.Engine{}).Scan(ctx, o, emit)
			},
			Complete: func(r scanner.Report) error {
				if *save != "" {
					return scanner.Save(*save, r)
				}
				return nil
			},
		})
	}
	enc := json.NewEncoder(os.Stdout)
	var previous *scanner.Report
	for {
		if human {
			label := o.Target.String()
			if o.Interface != "" {
				label += " on " + o.Interface
			}
			u.Intro(label, *profile)
		}
		output := scanOutput{}
		if (human && u.Color) || *asJSONL {
			output.Event = func(e scanner.Event) error {
				if human {
					u.Progress(e)
				}
				if *asJSONL {
					return enc.Encode(e)
				}
				return nil
			}
		}
		if *save != "" {
			output.Save = func(r scanner.Report) error { return scanner.Save(*save, r) }
		}
		output.Report = func(report scanner.Report) error {
			if human {
				view := ui.New(os.Stdout, *noColor)
				view.Report(report)
				if *details {
					view.Details(report)
				}
				return nil
			}
			if *asJSON {
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			if *asJSONL {
				return enc.Encode(struct {
					Type   string         `json:"type"`
					Report scanner.Report `json:"report"`
				}{"report", report})
			}
			return writeCSV(os.Stdout, report)
		}
		report, err := scanWithOutput(ctx, func(ctx context.Context, emit func(scanner.Event)) (scanner.Report, error) {
			r, err := (scanner.Engine{}).Scan(ctx, o, emit)
			if human {
				u.Clear()
			}
			return r, err
		}, output)
		if err != nil {
			return err
		}
		if previous != nil && !report.Cancelled {
			changes := scanner.Diff(*previous, report)
			if *asJSONL {
				if err = enc.Encode(struct {
					Type    string           `json:"type"`
					Changes []scanner.Change `json:"changes"`
				}{"changes", changes}); err != nil {
					return err
				}
			} else {
				for _, c := range changes {
					fmt.Printf("  %s %-15s %s\n", c.Type, c.IP, scanner.CleanText(c.Detail))
				}
			}
		}
		previous = &report
		if !watch || ctx.Err() != nil {
			return nil
		}
		timer := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
func writeCSV(w io.Writer, r scanner.Report) error {
	c := csv.NewWriter(w)
	if err := c.Write([]string{"ip", "mac", "vendor", "names", "ports", "evidence", "reported_name", "manufacturer", "model", "model_candidates", "firmware", "firmware_version", "mac_address_role", "mac_address_role_id", "service_fingerprints"}); err != nil {
		return err
	}
	for _, d := range r.Devices {
		var p []string
		for _, v := range d.Ports {
			p = append(p, strconv.Itoa(int(v.Number)))
		}
		row := []string{d.IP.String(), d.MAC, d.Vendor.Name, strings.Join(d.Names, ";"), strings.Join(p, ";"), strings.Join(d.Evidence, ";")}
		if d.Identity != nil {
			row = append(row, d.Identity.Name, d.Identity.Manufacturer, d.Identity.Model, strings.Join(d.Identity.ModelNames, ";"), d.Identity.Firmware, d.Identity.FirmwareVersion)
		} else {
			row = append(row, "", "", "", "", "", "")
		}
		if role := d.Vendor.AddressRole; role != nil {
			row = append(row, role.Name, strconv.Itoa(int(role.Identifier)))
		} else {
			row = append(row, "", "")
		}
		var matches []string
		for _, port := range d.Ports {
			if port.Fingerprint != nil {
				matches = append(matches, fmt.Sprintf("%d/%s: %s", port.Number, port.Service, port.Fingerprint.Summary()))
			}
		}
		row = append(row, strings.Join(matches, ";"))
		for i, s := range row {
			if len(s) > 0 && strings.ContainsAny(s[:1], "=+-@\t\r") {
				row[i] = "'" + s
			}
		}
		if err := c.Write(row); err != nil {
			return err
		}
	}
	c.Flush()
	return c.Error()
}
func wake(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: lantern wake MAC [broadcast-IP]")
	}
	mac, err := net.ParseMAC(args[0])
	if err != nil || len(mac) != 6 {
		return errors.New("expected a 48-bit MAC address")
	}
	address := "255.255.255.255"
	if len(args) == 2 {
		address = args[1]
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return errors.New("broadcast address must be IPv4")
	}
	packet := []byte{255, 255, 255, 255, 255, 255}
	for range 16 {
		packet = append(packet, mac...)
	}
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 9})
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write(packet)
	if err == nil {
		fmt.Println("Wake packet sent to", mac.String(), "via", address)
	}
	return err
}
func demo() scanner.Report {
	r := scanner.Report{Schema: 1, Target: "192.168.1.0/24", Probed: 254, Targets: 254, DurationMS: 742}
	data := `[{"ip":"192.168.1.1","mac":"00:11:22:33:44:55","names":["gateway.home"],"vendor":{"name":"Example Networks"},"ports":[{"port":80,"service":"http"},{"port":443,"service":"https"}],"evidence":["icmp"]},{"ip":"192.168.1.12","mac":"ac:de:48:12:34:56","names":["studio-mac.local"],"ports":[{"port":22,"service":"ssh"}],"evidence":["tcp-open"]},{"ip":"192.168.1.24","mac":"02:12:34:56:78:90","vendor":{"private":true},"evidence":["neighbor-cache"]},{"ip":"192.168.1.40","mac":"00:80:77:12:34:56","names":["office-printer.local"],"ports":[{"port":631,"service":"ipp"},{"port":9100,"service":"printer"}],"evidence":["tcp-open"]}]`
	json.Unmarshal([]byte(data), &r.Devices)
	return r
}

func demoCommand(args []string) error {
	f := flag.NewFlagSet("demo", flag.ContinueOnError)
	watch := f.Bool("watch", false, "preview the interactive dashboard without scanning")
	noColor := f.Bool("no-color", false, "disable color")
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("usage: lantern demo [--watch] [--no-color]")
	}
	if !*watch {
		u := ui.New(os.Stdout, *noColor)
		u.Intro("192.168.1.0/24", "DEMO · synthetic data")
		u.Report(demo())
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cycle := 0
	return ui.RunWatch(ctx, os.Stdin, os.Stdout, ui.WatchOptions{Target: "192.168.1.0/24", Profile: "DEMO · synthetic data", Interval: 3 * time.Second, NoColor: *noColor,
		Scan: func(ctx context.Context, emit func(scanner.Event)) (scanner.Report, error) {
			r := demo()
			r.Started = time.Now()
			cycle++
			if cycle%2 == 0 {
				r.Devices = r.Devices[:3]
			}
			for i := range r.Devices {
				timer := time.NewTimer(120 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					r.Devices = r.Devices[:i]
					r.Cancelled = true
					r.DurationMS = time.Since(r.Started).Milliseconds()
					return r, nil
				case <-timer.C:
				}
				emit(scanner.Event{Type: "device", Device: &r.Devices[i]})
				emit(scanner.Event{Type: "progress", Completed: i + 1, Total: len(r.Devices)})
			}
			r.DurationMS = time.Since(r.Started).Milliseconds()
			return r, nil
		}})
}
