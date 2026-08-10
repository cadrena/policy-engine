//go:build !darwin && !linux

package sqlite

func classifyFilesystem(string) error { return errUnsupportedFilesystem }
