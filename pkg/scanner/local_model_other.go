//go:build !darwin

package scanner

func localHardwareModel() (string, error) { return "", nil }
