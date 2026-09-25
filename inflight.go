package main

import "sync"

// inflightScans tracks which repos currently have a background scan running, so
// the firewall launches AT MOST ONE scan per repo (D18, trigger/dedup): the first
// cold pull starts the scan; concurrent and repeated pulls during that scan get
// the immediate verdict-pending 503 instead of piling on duplicate scans — this is
// what kills D12's "9× in one install" fan-out.
//
// This is EPHEMERAL coordination, not durable state: a firewall restart harmlessly
// forgets what was in flight and simply re-triggers on the next cold pull.
// Cross-replica dedup (a shared "scanning" marker in the DB) is deliberately
// deferred — per-replica dedup already removes the dominant single-install fan-out.
type inflightScans struct {
	mu      sync.Mutex
	running map[string]bool
}

func newInflightScans() *inflightScans {
	return &inflightScans{running: make(map[string]bool)}
}

// begin claims the scan slot for repo. It returns true to exactly ONE caller — the
// one that should launch the scan — and false to every other caller while that scan
// is in flight. Nil-safe (a hand-built test Firewall degrades to "no dedup", never
// a panic).
func (s *inflightScans) begin(repo string) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[repo] {
		return false
	}
	s.running[repo] = true
	return true
}

// done releases the slot when a scan finishes (success OR failure), so a later pull
// can trigger a fresh scan — important after a transient failure that left no
// durable result to read.
func (s *inflightScans) done(repo string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.running, repo)
}

// isRunning reports whether a scan is currently in flight for repo. Used by tests
// to wait for a background scan to finish — including the transient-failure case,
// which writes nothing durable to poll on.
func (s *inflightScans) isRunning(repo string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[repo]
}
