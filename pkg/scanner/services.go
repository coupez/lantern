package scanner

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/iana-tcp.tsv.gz
var serviceData []byte
var serviceOnce sync.Once
var registeredServices map[uint16]string

func serviceName(port uint16) string {
	if s := Services[port]; s != "" {
		return s
	}
	serviceOnce.Do(func() {
		registeredServices = map[uint16]string{}
		z, err := gzip.NewReader(bytes.NewReader(serviceData))
		if err != nil {
			panic(err)
		}
		defer z.Close()
		scan := bufio.NewScanner(z)
		for scan.Scan() {
			p, n, ok := strings.Cut(scan.Text(), "\t")
			if ok {
				v, _ := strconv.Atoi(p)
				registeredServices[uint16(v)] = n
			}
		}
		if err := scan.Err(); err != nil {
			panic(err)
		}
	})
	if s := registeredServices[port]; s != "" {
		return s
	}
	return "unknown"
}
