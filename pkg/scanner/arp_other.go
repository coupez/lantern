//go:build !darwin && !linux

package scanner

import (
	"fmt"
	"net"
)

func openEthernet(*net.Interface, uint16, uint32) (frameConn, error) {
	return nil, fmt.Errorf("direct Ethernet discovery is supported on macOS and Linux")
}
