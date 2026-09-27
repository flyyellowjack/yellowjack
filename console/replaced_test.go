package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The approval service marks a silent replica that a redeploy REPLACED (approval/replaced.go).
// The console drops those, so a healthy fleet does not read "1 of 3 not reporting" for ever,
// and KEEPS a silent replica nothing replaced, because that one may be a dead gate.
func TestHealthClientDropsReplacedReplicasOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"instance":"new","ecosystem":"npm","reported_at":"2026-09-25T12:00:00Z"},
			{"instance":"old","ecosystem":"npm","reported_at":"2026-09-25T10:00:00Z","replaced_by":"new"},
			{"instance":"dead","ecosystem":"pypi","reported_at":"2026-09-25T10:00:00Z"}]`))
	}))
	defer srv.Close()
	rows, err := (&approvalHTTPClient{baseURL: srv.URL, http: srv.Client()}).ListInstanceHealth()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range rows {
		got[h.Instance] = true
	}
	if got["old"] {
		t.Error("a replica the approval service marked replaced is still counted")
	}
	if !got["dead"] || !got["new"] {
		t.Errorf("the client dropped a replica it must keep: %v", got)
	}
}
