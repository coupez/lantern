package scanner

import (
	"net/netip"
	"slices"
	"testing"
)

func ubiquitiDiffDevice(ip string) Device {
	return Device{
		IP:       netip.MustParseAddr(ip),
		Evidence: []string{"ubiquiti", "tcp-open"},
		Names:    []string{"ubiquiti-device"},
		Ports:    []Port{{Number: 443, Service: "https"}},
		Kind:     "network device",
		Identity: &Identity{Name: "Ubiquiti device", Manufacturer: "Ubiquiti", Model: "Model A", FirmwareVersion: "1.0.0"},
	}
}

func TestDiffUbiquitiCoverageChangeDoesNotEraseIdentity(t *testing.T) {
	beforeDevice := ubiquitiDiffDevice("192.0.2.8")
	afterDevice := beforeDevice.Clone()
	afterDevice.Evidence = []string{"tcp-open"}
	afterDevice.Names = nil
	afterDevice.Identity = nil
	afterDevice.Kind = ""
	before := Report{Coverage: &ScanCoverage{Ubiquiti: true, TCPPorts: []uint16{443}}, Devices: []Device{beforeDevice}}
	after := Report{Coverage: &ScanCoverage{Ubiquiti: false, TCPPorts: []uint16{443}}, Devices: []Device{afterDevice}}
	changes := Diff(before, after)
	if len(changes) != 1 || changes[0].Type != "scan" || changes[0].Field != "coverage" {
		t.Fatalf("coverage change fabricated discovery loss: %#v", changes)
	}
	if !slices.Contains(changes[0].Before, "ubiquiti=true") || !slices.Contains(changes[0].After, "ubiquiti=false") {
		t.Fatalf("coverage does not expose Ubiquiti setting: %#v", changes[0])
	}
}

func TestDiffIncompleteUbiquitiSuppressesDiscoveryChangesButRetainsPorts(t *testing.T) {
	beforeDevice := ubiquitiDiffDevice("192.0.2.8")
	afterDevice := beforeDevice.Clone()
	afterDevice.Evidence = []string{"tcp-open"}
	afterDevice.Names = nil
	afterDevice.Identity = nil
	afterDevice.Kind = ""
	afterDevice.Ports = []Port{{Number: 80, Service: "http"}}
	before := Report{Coverage: &ScanCoverage{Ubiquiti: true, TCPPorts: []uint16{80, 443}}, Devices: []Device{beforeDevice, {IP: netip.MustParseAddr("192.0.2.9"), Evidence: []string{"ubiquiti"}}}}
	after := Report{Coverage: &ScanCoverage{Ubiquiti: true, TCPPorts: []uint16{80, 443}}, IncompleteMethods: []string{"ubiquiti"}, Devices: []Device{afterDevice}}
	changes := Diff(before, after)
	fields := map[string]bool{}
	for _, change := range changes {
		fields[change.Field] = true
	}
	if !fields["ports"] {
		t.Fatalf("Ubiquiti failure hid independent TCP change: %#v", changes)
	}
	for _, field := range []string{"reachability", "names", "identity.name", "identity.manufacturer", "identity.model", "identity.firmware_version", "kind"} {
		if fields[field] {
			t.Fatalf("Ubiquiti failure fabricated dependent %s change: %#v", field, changes)
		}
	}
	for _, change := range changes {
		if change.Type == "missing" {
			t.Fatalf("Ubiquiti failure declared absent device: %#v", changes)
		}
	}
}
