package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"lantern/internal/ui"
	"lantern/pkg/scanner"
	"lantern/pkg/vendors"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "0.1.0-dev"

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
		fmt.Println("lantern", version)
		return nil
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
		fmt.Printf("Lantern %s · %s/%s\nOffline vendor assignments: %d\n", version, runtime.GOOS, runtime.GOARCH, vendors.Count())
		n, err := scanner.Networks()
		if err != nil {
			return err
		}
		for _, v := range n {
			fmt.Printf("Network: %s on %s\n", v.CIDR, v.Interface)
		}
		fmt.Println("Discovery: ICMP echo + TCP connect + neighbor cache\nNo account, cloud lookup, telemetry, or root required on macOS.\nLinux ICMP availability depends on ping_group_range; TCP remains available.")
		return nil
	case "wake":
		return wake(args)
	case "demo":
		u := ui.New(os.Stdout, false)
		u.Intro("192.168.1.0/24", "DEMO · synthetic data")
		u.Report(demo())
		return nil
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
  lantern watch [CIDR]            Repeat scans and report changes
  lantern interfaces              List available IPv4/IPv6 networks
  lantern lookup MAC              Identify a MAC vendor offline
  lantern vendors [sources]       Database size and provenance
  lantern diff before.json after.json
  lantern wake MAC [broadcast-IP] Send a Wake-on-LAN packet
  lantern doctor                  Check local capabilities
  lantern demo                    Preview the CLI with sample data

  Scan options
    --profile quick|standard|deep  Default: standard
    --ports 22,80,443,8000-8100     Custom TCP ports (or none)
    --timeout 300ms                Per-probe deadline
    --concurrency 512              Maximum concurrent TCP probes
    --interface en0                Select local network / IPv6 zone
    --ipv6                         Discover local IPv6 neighbors
    --arp                          Direct IPv4 ARP (needs raw link access)
    --json | --jsonl | --csv        Structured output
    --save scan.json               Save a snapshot atomically
    --no-dns | --no-icmp            Disable discovery components
    --no-multicast                  Skip mDNS and SSDP (quick default)
    --no-descriptions               Skip UPnP model/name reads
    --details                      Show full device records
    --banners                      Read SSH/HTTP/service banners
    --all-hosts                    Scan ports even on silent hosts
    --interval 10s                 Delay between watch scans
    --max-hosts 4096               Maximum target addresses
    --no-color                     Plain output (also NO_COLOR)

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
	value := map[string]bool{"profile": true, "ports": true, "timeout": true, "concurrency": true, "interface": true, "save": true, "interval": true, "max-hosts": true}
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
		o.Target, err = scanner.AutoTarget(*iface)
	}
	if err != nil {
		return err
	}
	o.Resolve = !*noDNS
	o.ICMP = !*noICMP
	o.Multicast = !*noMulticast
	o.Descriptions = !*noDescriptions
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	u := ui.New(os.Stderr, *noColor)
	human := formats == 0
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
		var outputErr error
		report, err := (scanner.Engine{}).Scan(ctx, o, func(e scanner.Event) {
			if human {
				u.Progress(e)
			}
			if *asJSONL && outputErr == nil {
				outputErr = enc.Encode(e)
			}
		})
		if err != nil {
			u.Clear()
			return err
		}
		if human {
			u.Clear()
		}
		if outputErr != nil {
			return outputErr
		}
		if *save != "" {
			if err = scanner.Save(*save, report); err != nil {
				return err
			}
		}
		if human {
			view := ui.New(os.Stdout, *noColor)
			view.Report(report)
			if *details {
				view.Details(report)
			}
		} else if *asJSON {
			enc.SetIndent("", "  ")
			if err = enc.Encode(report); err != nil {
				return err
			}
		} else if *asJSONL {
			if err = enc.Encode(struct {
				Type   string         `json:"type"`
				Report scanner.Report `json:"report"`
			}{"report", report}); err != nil {
				return err
			}
		} else {
			if err = writeCSV(os.Stdout, report); err != nil {
				return err
			}
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
	if err := c.Write([]string{"ip", "mac", "vendor", "names", "ports", "evidence", "reported_name", "manufacturer", "model"}); err != nil {
		return err
	}
	for _, d := range r.Devices {
		var p []string
		for _, v := range d.Ports {
			p = append(p, strconv.Itoa(int(v.Number)))
		}
		row := []string{d.IP.String(), d.MAC, d.Vendor.Name, strings.Join(d.Names, ";"), strings.Join(p, ";"), strings.Join(d.Evidence, ";")}
		if d.Identity != nil {
			row = append(row, d.Identity.Name, d.Identity.Manufacturer, d.Identity.Model)
		} else {
			row = append(row, "", "", "")
		}
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
