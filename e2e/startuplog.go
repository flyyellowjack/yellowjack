//go:build e2e

package e2e

import "strings"

// startupNoise returns the ERROR/WARN/FATAL lines a firewall emitted while booting
// (issue #19).
//
// Split out as a pure function for the reason parseDecisions is: fwLog.String()
// shells out to `docker logs`, so a detector that only existed inside a container
// leg could not be tested — and an assertion nobody has watched fail is exactly the
// "automation that reports success" trap. This one has a negative control in
// startuplog_test.go, which runs without a docker runner.
//
// WHY THIS ASSERTION EXISTS. Standing up Artifactory, one missing prerequisite
// produced six unrelated FATAL lines while the healthy path ALSO emitted 404s and
// "required node services are missing or unhealthy". An operator could not tell
// healthy from broken in either direction. Noisy-when-healthy destroys
// diagnosability just as effectively as silent-when-broken — so "a clean boot is
// clean" is the property, and it only stays true if something fails when it stops
// being true.
//
// Scanning is deliberately limited to the BOOT, up to and including the byte-gate
// line that ends the startup banner. Past that point the log is request traffic,
// where a WARNING is a legitimate report about a package rather than a complaint
// about our own configuration.
func startupNoise(logText string) []string {
	var out []string
	for _, line := range strings.Split(logText, "\n") {
		if isStartupNoise(line) {
			out = append(out, strings.TrimSpace(line))
		}
		// The banner's last line. Everything after it is traffic, not boot.
		if strings.Contains(line, "artifact byte gate:") || strings.Contains(line, "scanner service:") {
			break
		}
	}
	return out
}

// isStartupNoise reports whether one boot line is a complaint.
//
// Matching is on the SEVERITY TOKEN, not on substrings of prose: several healthy
// banner lines legitimately contain the word "error" or "warning" inside an
// explanation, and a naive strings.Contains would fail a clean boot — which would
// get the assertion deleted rather than the noise fixed.
func isStartupNoise(line string) bool {
	for _, token := range []string{"WARNING:", "ERROR:", "FATAL:", "panic:"} {
		if strings.Contains(line, token) {
			return true
		}
	}
	return false
}
