package main

import (
	"log"
	"net"
	"strings"
)

// feedCredential is the feed's access key source (D366), or nil when none is configured.
// Its log lines are labelled feed-auth, so they cannot be mistaken for the registry's.
func feedCredential(path string) credentialSource {
	if path == "" {
		return nil
	}
	return fileCredentialFor("feed-auth", "feed pulls", path, log.Printf, credFileTTL)
}

// isLoopbackHost reports whether a URL host is this machine, the one place plain http may
// carry the feed key.
func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
