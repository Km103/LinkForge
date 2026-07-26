//go:build !linux && !windows

package config

func defaultPathInterfaces() map[string]bool { return nil }
