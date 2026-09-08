//go:build darwin || linux

package ui

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

const terminalInputSupported = true

func readWatchKeys(ctx context.Context, in *os.File, keys chan<- string) error {
	defer close(keys)
	decoder := keyDecoder{}
	poll := []unix.PollFd{{Fd: int32(in.Fd()), Events: unix.POLLIN}}
	buf := make([]byte, 256)
	send := func(list []string) bool {
		for _, key := range list {
			select {
			case keys <- key:
			case <-ctx.Done():
				return false
			}
		}
		return true
	}
	for ctx.Err() == nil {
		n, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			if !send(decoder.flushEscape()) {
				return nil
			}
			continue
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			count, e := unix.Read(int(in.Fd()), buf)
			if errors.Is(e, unix.EINTR) {
				continue
			}
			if e != nil {
				return e
			}
			if count == 0 {
				return nil
			}
			if !send(decoder.feed(string(buf[:count]))) {
				return nil
			}
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return nil
		}
	}
	return nil
}
