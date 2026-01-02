//go:build !linux

package dynscan

// LinuxRemoteEndpoints is a stub on non-Linux platforms.
func LinuxRemoteEndpoints() map[string]struct{} {
	return map[string]struct{}{}
}
