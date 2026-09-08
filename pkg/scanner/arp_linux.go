//go:build linux

package scanner

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"time"
)

type packetARP struct {
	file   *os.File
	buffer []byte
}

func openEthernet(iface *net.Interface, etherType uint16, capture uint32) (frameConn, error) {
	var protocol [2]byte
	binary.BigEndian.PutUint16(protocol[:], etherType)
	p := binary.NativeEndian.Uint16(protocol[:])
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(p))
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: p, Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "lantern-ethernet")
	if err = f.SetReadDeadline(time.Time{}); err != nil {
		f.Close()
		return nil, fmt.Errorf("packet deadlines: %w", err)
	}
	return &packetARP{file: f, buffer: make([]byte, max(capture, 64))}, nil
}
func (c *packetARP) ReadFrame() ([]byte, error) {
	n, err := c.file.Read(c.buffer)
	return c.buffer[:n], err
}
func (c *packetARP) WriteFrame(b []byte) error {
	n, err := c.file.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
func (c *packetARP) SetReadDeadline(t time.Time) error  { return c.file.SetReadDeadline(t) }
func (c *packetARP) SetWriteDeadline(t time.Time) error { return c.file.SetWriteDeadline(t) }
func (c *packetARP) Close() error                       { return c.file.Close() }
