// Package fipsmode reports whether this binary is running Go's FIPS 140-3 cryptographic
// module, as one startup line every Yellow Jack service prints (D374).
//
// The published images build with GOFIPS140 set to the certified module (see the
// Dockerfiles), which also makes the binary start in FIPS mode (GODEBUG fips140=on).
// The line exists so an operator, or an auditor reading the operator's logs, can see
// that from the running process rather than from our documentation.
package fipsmode

import (
	"crypto/fips140"
	"runtime/debug"
)

// Line is the startup banner line: whether FIPS 140-3 mode is on, and which Go
// Cryptographic Module the binary was built against.
func Line() string {
	return format(fips140.Enabled(), buildSetting("GOFIPS140"))
}

// buildSetting reads one setting the go command recorded in the binary at build time.
func buildSetting(key string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

func format(enabled bool, module string) string {
	built := module != "" && module != "off"
	switch {
	case enabled && built:
		return "FIPS 140-3 mode: ON (Go Cryptographic Module " + module + ")"
	case enabled:
		// GODEBUG=fips140=on on a binary built without GOFIPS140: FIPS mode, but on the
		// module in the Go source tree rather than a frozen, certified snapshot.
		return "FIPS 140-3 mode: ON, but on the in-tree module, not a certified one (build with GOFIPS140 to pin it)"
	default:
		return "FIPS 140-3 mode: off (the published images build it on; this binary was built without GOFIPS140)"
	}
}
