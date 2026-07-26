//go:build linux

package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func defaultPathInterfaces() map[string]bool {
	result := make(map[string]bool)
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err == nil && flags&1 != 0 {
			result[fields[0]] = true
		}
	}
	return result
}
