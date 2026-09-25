package main

import (
	"log"
	"net/http"
	"time"
)

// listAlerts returns the currently-active default alerts (GET /v1/alerts).
//
// Computed on READ from live data rather than served from a table a sweep populates.
// That means what the console shows is never stale, an alert clears the moment its cause
// does, and there is no background goroutine whose failure would silently freeze the
// alert list at whatever it last managed to write. The cost is one summary query and one
// health query per page load, which is the same order as the dashboard's own tiles.
func (srv *server) listAlerts(w http.ResponseWriter, r *http.Request) {
	p := defaultAlertParams()
	now := time.Now().UTC()

	health, err := srv.store.ListInstanceHealth()
	if err != nil {
		log.Printf("alerts: list instance health: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	// The transfer-failure count comes from a WINDOWED summary, never the lifetime one:
	// counted over all history, a single truncated download would alert forever (see
	// evaluateAlerts). Half-open on From, matching every other flow read.
	window, err := srv.store.FlowSummary(FlowFilter{From: now.Add(-p.Window), To: now})
	if err != nil {
		log.Printf("alerts: flow summary: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	alerts := evaluateAlerts(now, health, window, p)
	if alerts == nil {
		// [] rather than null so a console can range over it unguarded — and so "no
		// alerts" is an explicit, checkable answer rather than an absent field.
		alerts = []Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}
