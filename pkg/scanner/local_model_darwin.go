//go:build darwin

package scanner

import "golang.org/x/sys/unix"

// This read does not launch a process, require privilege, or collect serials.
func localHardwareModel() (string, error) { return unix.Sysctl("hw.model") }
