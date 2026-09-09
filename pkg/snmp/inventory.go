package snmp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	sysDescrOID  = "1.3.6.1.2.1.1.1.0"
	sysObjectOID = "1.3.6.1.2.1.1.2.0"
	sysNameOID   = "1.3.6.1.2.1.1.5.0"
	classOID     = "1.3.6.1.2.1.47.1.1.1.1.5"
	parentOID    = "1.3.6.1.2.1.47.1.1.1.1.4"
	mfgOID       = "1.3.6.1.2.1.47.1.1.1.1.12"
	modelOID     = "1.3.6.1.2.1.47.1.1.1.1.13"
)

type System struct {
	Description string `json:"description,omitempty"`
	ObjectID    string `json:"object_id,omitempty"`
	Name        string `json:"name,omitempty"`
}

type Entity struct {
	Index        int64  `json:"index"`
	Class        int64  `json:"class"`
	Parent       *int64 `json:"parent,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
}

type Report struct {
	Target          string   `json:"target"`
	System          System   `json:"system"`
	Entities        []Entity `json:"entities,omitempty"`
	EntityStatus    string   `json:"entity_status"`
	Manufacturer    string   `json:"manufacturer,omitempty"`
	Model           string   `json:"model,omitempty"`
	ManufacturerOID string   `json:"manufacturer_oid,omitempty"`
	ModelOID        string   `json:"model_oid,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

// Read collects a bounded, read-only SNMPv2c inventory from exactly one peer.
func Read(ctx context.Context, target netip.AddrPort, credentials Credentials, timeout time.Duration) (Report, error) {
	report := Report{Target: target.String(), EntityStatus: "failed"}
	if timeout <= 0 || timeout > 30*time.Second || !validTarget(target) {
		return report, errors.New("invalid SNMP inventory target or timeout")
	}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if _, err := BuildGet(credentials, 1, []string{sysDescrOID}); err != nil {
		return report, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return report, fmt.Errorf("SNMP inventory connect: %w", err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer conn.Close()

	values, err := exchange(ctx, conn, credentials, func(id int32) ([]byte, error) {
		return BuildGet(credentials, id, []string{sysDescrOID, sysObjectOID, sysNameOID})
	})
	if err != nil {
		return report, fmt.Errorf("SNMP inventory system query: %w", err)
	}
	system, unsupported, err := parseSystem(values)
	report.System = system
	if err != nil {
		return report, fmt.Errorf("SNMP inventory system response: %w", err)
	}
	if unsupported {
		report.Warnings = append(report.Warnings, "Some SNMP system fields are unavailable")
	}

	values, err = exchange(ctx, conn, credentials, func(id int32) ([]byte, error) { return BuildBulk(credentials, id, classOID, 33) })
	if err != nil {
		return report, fmt.Errorf("SNMP inventory entity-class query: %w", err)
	}
	entities, status, err := parseClasses(values)
	report.Entities, report.EntityStatus = entities, status
	if err != nil {
		return report, fmt.Errorf("SNMP inventory entity-class response: %w", err)
	}
	if (status != "complete" && status != "truncated") || len(entities) == 0 {
		if status == "unsupported" {
			report.Warnings = append(report.Warnings, "SNMP ENTITY-MIB physical class is unsupported")
		}
		return report, nil
	}

	chassis := make([]int, 0, len(entities))
	for i, entity := range entities {
		if entity.Class == 3 {
			chassis = append(chassis, i)
		}
	}
	if len(chassis) == 0 {
		return report, nil
	}
	oids := make([]string, 0, len(chassis)*3)
	for _, i := range chassis {
		index := fmt.Sprint(entities[i].Index)
		oids = append(oids, parentOID+"."+index, mfgOID+"."+index, modelOID+"."+index)
	}
	values, err = exchange(ctx, conn, credentials, func(id int32) ([]byte, error) { return BuildGet(credentials, id, oids) })
	if err != nil {
		report.EntityStatus = "failed"
		return report, fmt.Errorf("SNMP inventory chassis query: %w", err)
	}
	if err := fillChassis(entities, chassis, values, oids); err != nil {
		report.EntityStatus = "failed"
		return report, fmt.Errorf("SNMP inventory chassis response: %w", err)
	}
	report.Entities = entities
	promote(&report)
	return report, nil
}

func validTarget(target netip.AddrPort) bool {
	ip := target.Addr()
	base := ip.WithZone("")
	if !target.IsValid() || target.Port() == 0 || !base.IsValid() || ip.Is4In6() || !(base.IsGlobalUnicast() || base.IsLinkLocalUnicast() || base.IsLoopback()) {
		return false
	}
	if base.Is6() && base.IsLinkLocalUnicast() {
		return validZone(ip.Zone())
	}
	return ip.Zone() == "" || validZone(ip.Zone())
}

func requestID() (int32, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(^uint32(0)>>1)))
	if err != nil {
		return 0, err
	}
	return int32(n.Int64() + 1), nil
}

func exchange(ctx context.Context, conn *net.UDPConn, credentials Credentials, build func(int32) ([]byte, error)) ([]Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := requestID()
	if err != nil {
		return nil, err
	}
	packet, err := build(id)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err = conn.Write(packet); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	b := make([]byte, maxMessage+1)
	n, err := conn.Read(b)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if n > maxMessage {
		return nil, errors.New("SNMP response exceeds limit")
	}
	return ParseResponse(b[:n], credentials, id)
}

func parseSystem(values []Value) (System, bool, error) {
	if !exactBindings(values, []string{sysDescrOID, sysObjectOID, sysNameOID}) {
		return System{}, false, errors.New("unexpected system bindings")
	}
	by := byOID(values)
	out, unsupported := System{}, false
	if v := by[sysDescrOID]; isNoSuch(v) {
		unsupported = true
	} else if s, ok := text(v); ok {
		out.Description = s
	} else {
		return out, false, errors.New("invalid sysDescr")
	}
	if v := by[sysObjectOID]; isNoSuch(v) {
		unsupported = true
	} else if v.Kind == "oid" && validOID(v.Text) {
		out.ObjectID = v.Text
	} else {
		return out, false, errors.New("invalid sysObjectID")
	}
	if v := by[sysNameOID]; isNoSuch(v) {
		unsupported = true
	} else if s, ok := text(v); ok {
		out.Name = s
	} else {
		return out, false, errors.New("invalid sysName")
	}
	return out, unsupported, nil
}

func parseClasses(values []Value) ([]Entity, string, error) {
	if len(values) == 0 || len(values) > 33 {
		return nil, "failed", errors.New("invalid class response binding count")
	}
	entities := make([]Entity, 0, 32)
	base, _ := parseOID(classOID)
	last := base
	leftColumn, ended := false, false
	classCount := 0
	for _, value := range values {
		arcs, err := parseOID(value.OID)
		if err != nil {
			return nil, "failed", err
		}
		if value.Kind == "end-of-mib" {
			// GETBULK can repeat endOfMibView in its remaining repetitions.
			// Its name stays at the previous binding's name (or the request).
			if oidCompare(arcs, last) != 0 {
				return nil, "failed", errors.New("invalid end-of-MIB binding")
			}
			ended = true
			continue
		}
		if isNoSuch(value) {
			if len(values) == 1 && value.OID == classOID {
				return nil, "unsupported", nil
			}
			return nil, "failed", errors.New("unexpected class exception")
		}
		if ended || oidCompare(arcs, last) <= 0 {
			return nil, "failed", errors.New("unordered entity-class response")
		}
		last = arcs
		if strings.HasPrefix(value.OID, classOID+".") {
			index, ok := indexedOID(value.OID, classOID)
			if !ok || leftColumn || value.Kind != "integer" || value.Integer < 1 || value.Integer > 255 {
				return nil, "failed", errors.New("invalid entity-class binding")
			}
			classCount++
			if len(entities) < 32 {
				entities = append(entities, Entity{Index: index, Class: value.Integer})
			}
		} else {
			leftColumn = true
		}
	}
	if classCount <= 32 && (leftColumn || ended) {
		return entities, "complete", nil
	}
	return entities, "truncated", nil
}

func fillChassis(entities []Entity, chassis []int, values []Value, oids []string) error {
	if !exactBindings(values, oids) {
		return errors.New("unexpected chassis binding count")
	}
	byOID := byOID(values)
	for _, value := range values {
		if value.Kind == "end-of-mib" {
			return errors.New("end of MIB in GET response")
		}
	}
	for _, i := range chassis {
		index := fmt.Sprint(entities[i].Index)
		parent := byOID[parentOID+"."+index]
		if !isNoSuch(parent) && (parent.Kind != "integer" || parent.Integer < 0 || parent.Integer > int64(^uint32(0)>>1)) {
			return errors.New("invalid chassis parent")
		}
		manufacturer := ""
		if v := byOID[mfgOID+"."+index]; !isNoSuch(v) {
			var ok bool
			manufacturer, ok = text(v)
			if !ok {
				return errors.New("invalid chassis manufacturer")
			}
		}
		model := ""
		if v := byOID[modelOID+"."+index]; !isNoSuch(v) {
			var ok bool
			model, ok = text(v)
			if !ok {
				return errors.New("invalid chassis model")
			}
		}
		if !isNoSuch(parent) {
			p := parent.Integer
			entities[i].Parent = &p
		}
		entities[i].Manufacturer, entities[i].Model = manufacturer, model
	}
	return nil
}

func promote(report *Report) {
	if report.EntityStatus != "complete" {
		return
	}
	roots := []Entity{}
	for _, entity := range report.Entities {
		if entity.Class == 3 {
			if entity.Parent == nil {
				return
			}
			if *entity.Parent == 0 {
				roots = append(roots, entity)
			}
		}
	}
	if len(roots) == 1 && roots[0].Model != "" {
		report.Model, report.Manufacturer = roots[0].Model, roots[0].Manufacturer
		report.ModelOID = modelOID + "." + fmt.Sprint(roots[0].Index)
		if report.Manufacturer != "" {
			report.ManufacturerOID = mfgOID + "." + fmt.Sprint(roots[0].Index)
		}
	}
}

func isNoSuch(v Value) bool { return v.Kind == "no-such-object" || v.Kind == "no-such-instance" }
func byOID(values []Value) map[string]Value {
	out := make(map[string]Value, len(values))
	for _, v := range values {
		out[v.OID] = v
	}
	return out
}
func exactBindings(values []Value, want []string) bool {
	if len(values) != len(want) {
		return false
	}
	seen, need := map[string]bool{}, map[string]bool{}
	for _, oid := range want {
		need[oid] = true
	}
	for _, v := range values {
		if !need[v.OID] || seen[v.OID] {
			return false
		}
		seen[v.OID] = true
	}
	return true
}
func oidCompare(a, b []uint32) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
func text(v Value) (string, bool) {
	if v.Kind != "octets" || len(v.Bytes) > 2048 || !utf8.Valid(v.Bytes) {
		return "", false
	}
	s := strings.TrimSpace(string(v.Bytes))
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", false
		}
	}
	return s, true
}
func validOID(s string) bool { _, err := parseOID(s); return err == nil }
func indexedOID(oid, base string) (int64, bool) {
	prefix := base + "."
	if !strings.HasPrefix(oid, prefix) {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimPrefix(oid, prefix), 10, 32)
	return n, err == nil && n > 0
}
func validZone(zone string) bool {
	if zone == "" || len(zone) > 255 || !utf8.ValidString(zone) {
		return false
	}
	for _, r := range zone {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
