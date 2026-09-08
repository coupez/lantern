//go:build darwin

package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

type bpfARP struct {
	file    *os.File
	buffer  []byte
	pending []byte
}

func openARP(iface *net.Interface) (arpConn, error) {
	var fd int
	var err error
	for i := 0; i < 256; i++ {
		fd, err = unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EBUSY) {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (arpConn, error) { unix.Close(fd); return nil, err }
	if _, err = syscall.SetBpfBuflen(fd, 32768); err != nil {
		return closeOnError(err)
	}
	if err = syscall.SetBpfInterface(fd, iface.Name); err != nil {
		return closeOnError(err)
	}
	dlt, err := syscall.BpfDatalink(fd)
	if err != nil {
		return closeOnError(err)
	}
	if dlt != syscall.DLT_EN10MB {
		return closeOnError(fmt.Errorf("interface uses unsupported link type %d", dlt))
	}
	if err = syscall.SetBpfImmediate(fd, 1); err != nil {
		return closeOnError(err)
	}
	if err = syscall.SetBpfHeadercmpl(fd, 1); err != nil {
		return closeOnError(err)
	}
	// Capture only ARP frames, and only the first 64 bytes needed for decoding.
	filter := []syscall.BpfInsn{{Code: 0x28, K: 12}, {Code: 0x15, K: 0x0806, Jf: 1}, {Code: 0x06, K: 64}, {Code: 0x06, K: 0}}
	if err = syscall.SetBpf(fd, filter); err != nil {
		return closeOnError(err)
	}
	size, err := syscall.BpfBuflen(fd)
	if err != nil {
		return closeOnError(err)
	}
	if size < 64 || size > 512*1024 {
		return closeOnError(fmt.Errorf("invalid BPF buffer size %d", size))
	}
	f := os.NewFile(uintptr(fd), "lantern-arp")
	if err = f.SetReadDeadline(time.Time{}); err != nil {
		f.Close()
		return nil, err
	}
	return &bpfARP{file: f, buffer: make([]byte, size)}, nil
}
func (c *bpfARP) ReadFrame() ([]byte, error) {
	for {
		if len(c.pending) > 0 {
			frame, rest, err := splitBPF(c.pending)
			c.pending = rest
			return frame, err
		}
		n, err := c.file.Read(c.buffer)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
		c.pending = c.buffer[:n]
	}
}
func (c *bpfARP) WriteFrame(b []byte) error {
	n, err := c.file.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
func (c *bpfARP) SetReadDeadline(t time.Time) error  { return c.file.SetReadDeadline(t) }
func (c *bpfARP) SetWriteDeadline(t time.Time) error { return c.file.SetWriteDeadline(t) }
func (c *bpfARP) Close() error                       { return c.file.Close() }

// Darwin's bpf_hdr has a timeval32 and 4-byte record alignment on both supported
// architectures. Hdrlen includes padding and must be used instead of sizeof.
func splitBPF(b []byte) ([]byte, []byte, error) {
	if len(b) < 18 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	caplen := uint64(binary.NativeEndian.Uint32(b[8:12]))
	hdrlen := uint64(binary.NativeEndian.Uint16(b[16:18]))
	end := hdrlen + caplen
	if hdrlen < 18 || end > uint64(len(b)) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	next := (end + 3) &^ uint64(3)
	if next > uint64(len(b)) {
		next = uint64(len(b))
	}
	return b[hdrlen:end], b[next:], nil
}
