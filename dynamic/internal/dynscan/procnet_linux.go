//go:build linux

package dynscan

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

func LinuxRemoteEndpoints() map[string]struct{} {
	out := map[string]struct{}{}
	readProcNet("/proc/net/tcp", out)
	readProcNet("/proc/net/tcp6", out)
	readProcNet("/proc/net/udp", out)
	readProcNet("/proc/net/udp6", out)
	return out
}

func readProcNet(path string, out map[string]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		remote := fields[2] // rem_address
		ipPort, ok := parseProcNetAddr(remote)
		if !ok {
			continue
		}
		// ignore unspecified/loopback/empty remote
		if strings.HasSuffix(ipPort, ":0") ||
			strings.HasPrefix(ipPort, "0.0.0.0:") ||
			strings.HasPrefix(ipPort, "127.0.0.1:") ||
			strings.HasPrefix(ipPort, "[::]:") ||
			strings.HasPrefix(ipPort, "[::1]:") {
			continue
		}
		out[ipPort] = struct{}{}
	}
}

func parseProcNetAddr(v string) (string, bool) {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return "", false
	}
	ipHex, portHex := parts[0], parts[1]
	portBytes, err := hex.DecodeString(portHex)
	if err != nil || len(portBytes) != 2 {
		return "", false
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	// IPv4 is 8 hex chars in little-endian; IPv6 is 32 hex chars.
	switch len(ipHex) {
	case 8:
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 4 {
			return "", false
		}
		ip := net.IP{b[3], b[2], b[1], b[0]}
		return ip.String() + ":" + itoa(port), true
	case 32:
		b, err := hex.DecodeString(ipHex)
		if err != nil || len(b) != 16 {
			return "", false
		}
		// /proc/net/tcp6 uses little-endian 32-hex groups; simplest: reverse per 4 bytes
		ip := make(net.IP, 16)
		copy(ip, b)
		// Best-effort: reverse every 4 bytes
		for i := 0; i < 16; i += 4 {
			ip[i+0], ip[i+1], ip[i+2], ip[i+3] = ip[i+3], ip[i+2], ip[i+1], ip[i+0]
		}
		return "[" + ip.String() + "]:" + itoa(port), true
	default:
		return "", false
	}
}
