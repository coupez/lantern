//go:build !darwin && !linux

package scanner

import (
	"fmt"
	"net"
)

func openARP(*net.Interface) (arpConn, error) {
	return nil, fmt.Errorf("direct ARP is supported on macOS and Linux")
}
