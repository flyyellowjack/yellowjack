package main

import (
	"bytes"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewProxyServerIsQuiet pins where the compiled-policy line is allowed to be logged.
//
// The line belongs in main.go's startup banner. It was first written inside
// newProxyServer, which looks equivalent — the constructor runs once in production — but
// under test it runs once per case: in the mode matrix that was 3,840 of 3,853 output
// lines, which buried the very diff the matrix exists to show.
//
// That is a trap a comment cannot hold, because the natural place to write a startup log
// is next to the thing being started. So it is asserted instead: move the line back and
// this test fails.
func TestNewProxyServerIsQuiet(t *testing.T) {
	upstream := httptest.NewServer(nil)
	defer upstream.Close()

	cfg := Config{
		Ecosystem:        "npm",
		UpstreamRegistry: upstream.URL,
		UnscorablePolicy: "block",
		ScoreThreshold:   5.0,
		ScorecardMode:    "stub",
		ScoreCacheTTL:    time.Minute,
	}
	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	var buf bytes.Buffer
	restore := log.Writer()
	log.SetOutput(&buf)
	p := newProxyServer(cfg, fw)
	log.SetOutput(restore)

	if got := buf.String(); strings.TrimSpace(got) != "" {
		t.Errorf("newProxyServer logged %d bytes; the constructor must be silent because it\n"+
			"runs once per test case. Startup logging belongs in main.go.\nGot:\n%s",
			buf.Len(), got)
	}

	// The other half of the contract, and the reason this is a MOVE and not a deletion:
	// the policy must still reach the heartbeat (#32 Phase D / D4). A version that simply
	// dropped the log line would pass the assertion above while silently un-reporting the
	// posture to the control plane.
	if p.flowEmit == nil || p.flowEmit.policy == nil {
		t.Fatal("policy source not wired to the flow emitter: removing the log line must not stop the heartbeat reporting the posture (D4)")
	}
	// A SOURCE since D195, not a snapshot, so read through it. The distinction is the
	// point: a snapshot reports the policy this replica had at BOOT forever, and the
	// operator lists now change while the process runs.
	view := p.flowEmit.policyNow()
	if view == nil || len(view.Chains) == 0 || view.Digest == "" {
		t.Errorf("the reported policy is empty; the heartbeat would report nothing")
	}
}
