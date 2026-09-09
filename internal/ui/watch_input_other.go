//go:build !darwin && !linux

package ui

import (
	"context"
	"errors"
	"os"
)

const terminalInputSupported = false

func readWatchKeys(context.Context, *os.File, chan<- string) error {
	return errors.New("interactive watch is supported on macOS and Linux")
}
