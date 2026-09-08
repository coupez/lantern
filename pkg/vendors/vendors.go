// Package vendors provides offline longest-prefix IEEE MAC assignment lookup.
package vendors

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
)

//go:embed data/ieee.tsv.gz
var data []byte

//go:embed data/sources.json
var Sources string

// Match identifies the registered organization, not necessarily the device brand.
type Match struct {
	// AddressRole is independent of the registered organization in Name.
	AddressRole *AddressRole `json:"address_role,omitempty"`
	Name        string       `json:"name,omitempty"`
	Prefix      string       `json:"prefix,omitempty"`
	Registry    string       `json:"registry,omitempty"`
	Private     bool         `json:"private"`
	Multicast   bool         `json:"multicast"`
}

var once sync.Once
var index map[string]Match

func initIndex() {
	index = make(map[string]Match, 60000)
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	defer z.Close()
	s := bufio.NewScanner(z)
	for s.Scan() {
		f := strings.Split(s.Text(), "\t")
		if len(f) == 3 {
			index[f[0]] = Match{Name: f[1], Prefix: f[0], Registry: f[2]}
		}
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}
func Count() int { once.Do(initIndex); return len(index) }
func Lookup(mac string) (Match, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return Match{}, fmt.Errorf("invalid 48-bit MAC address %q", mac)
	}
	m := Match{Private: hw[0]&2 != 0, Multicast: hw[0]&1 != 0}
	if m.Private || m.Multicast {
		return m, nil
	}
	m.AddressRole = addressRole(hw)
	once.Do(initIndex)
	key := strings.ToUpper(hex.EncodeToString(hw))
	for _, n := range []int{9, 7, 6} {
		if v, ok := index[key[:n]]; ok {
			v.AddressRole = m.AddressRole
			return v, nil
		}
	}
	return m, nil
}
