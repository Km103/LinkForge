//go:build windows

package config

import (
	"os/exec"
	"strings"
)

func defaultPathInterfaces() map[string]bool {
	result := make(map[string]bool)
	output, err := exec.Command("route.exe", "print", "-4").Output()
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			result["ip:"+fields[3]] = true
		}
	}
	return result
}
