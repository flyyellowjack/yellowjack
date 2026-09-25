package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// The L2 score record is the second wire format the gate and the control plane share
// without a shared type (the first is the audit event, auditwire_test.go). #133 adds
// coverage to it -- what a score was computed over -- and the same silence would apply:
// a key the gate records that the control plane's ScoreRecord does not name is dropped
// on ingest, and the console could never show it.
func TestEveryScoreFieldTheGateRecordsIsStoredByTheControlPlane(t *testing.T) {
	emitted := jsonKeys(reflect.TypeOf(scoreRecord{}))
	if len(emitted) < 3 {
		t.Fatalf("read only %d json keys off the gate's scoreRecord; the reflection is broken", len(emitted))
	}
	if missing := keysNotStored(emitted, approvalStructKeys(t, "ScoreRecord", 3)); len(missing) > 0 {
		t.Errorf("the gate records score fields the control plane does not store: %v. Each one is silently "+
			"dropped on ingest. Add the field to approval/store.go's ScoreRecord (and its column in pgstore.go), "+
			"or stop sending it.", missing)
	}
}

// TestABackgroundScanRecordsWhatAPartialScoreWasComputedOver drives the real path: a
// scheduler reply with three low-weight checks errored passes the D271 floor, and the
// L2 write must carry the coverage with the number. The control is a complete report,
// which must record full coverage and nothing computed-without.
func TestABackgroundScanRecordsWhatAPartialScoreWasComputedOver(t *testing.T) {
	var got scoreRecord
	ap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			_ = json.NewDecoder(r.Body).Decode(&got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ap.Close()

	run := func(reply string) scoreRecord {
		got = scoreRecord{}
		f := floorFirewall(t, reply, "")
		f.cfg.ApprovalURL = ap.URL
		f.client = ap.Client()
		f.cache = newScoreCache(time.Minute, 8)
		f.runBackgroundScan("pkg", "gitlab.example/org/repo")
		return got
	}

	rec := run(partialReply("License", "CI-Tests", "Contributors"))
	if rec.Repo != "gitlab.example/org/repo" || rec.Score == nil || *rec.Score != 6.2 {
		t.Fatalf("the partial score was not recorded: %+v", rec)
	}
	if rec.ScoredChecks != 15 || rec.TotalChecks != 18 {
		t.Errorf("coverage recorded as %d of %d, want 15 of 18", rec.ScoredChecks, rec.TotalChecks)
	}
	if want := []string{"CI-Tests", "Contributors", "License"}; !reflect.DeepEqual(rec.ComputedWithout, want) {
		t.Errorf("computedWithout = %v, want %v (sorted)", rec.ComputedWithout, want)
	}

	full := run(partialReply())
	if full.Score == nil || *full.Score != 6.2 {
		t.Fatalf("control: the complete report was not recorded: %+v", full)
	}
	if full.ScoredChecks != 18 || full.TotalChecks != 18 || len(full.ComputedWithout) != 0 {
		t.Errorf("control: a complete report recorded a coverage shortfall: %+v", full)
	}
}
