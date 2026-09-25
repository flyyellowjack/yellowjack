package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// The HTTP surface of the flow dataset (#32 Phase C / C2):
//
//	POST /v1/flow            -> ingest a batch of pre-aggregated buckets (from the firewall)
//	GET  /v1/flow/summary    -> D81 Q2, "how much data is flowing through my system"
//	GET  /v1/flow/packages   -> D81 Q1, "which packages are the bulk of the data"
//	GET  /v1/flow/sources    -> D81 Q4, "which hosts are consuming the pipe"
//	GET  /v1/flow/series     -> D81 Q4, "why is it saturated RIGHT NOW"
//
// Named /v1/flow rather than /v1/metrics on purpose: "metrics" invites the assumption
// that this is a Prometheus exposition endpoint, which it deliberately is not (D80 chose
// a bespoke native dashboard over the furnish-Grafana path). "Flow" also matches the
// vocabulary the firewall side uses, and keeps the name away from scheduler "capacity",
// which already means scan-launcher slots.

// flowIngest is the POST body: one batch from one firewall instance.
type flowIngest struct {
	Instance string         `json:"instance"`
	Packages []FlowBucket   `json:"packages"`
	Sources  []FlowIPBucket `json:"sources"`
}

// maxFlowBatchBytes bounds a single ingest body. Generous next to a real batch (a few
// hundred rows) but finite, so a malformed or hostile sender cannot make us buffer
// without limit — the same posture as the metadata relay's cap.
const maxFlowBatchBytes = 8 << 20 // 8 MiB

// ingestFlow accepts a batch of counters and merges them additively.
//
// It answers 202 Accepted, not 200: the batch is telemetry that has been durably merged,
// but the sender must NOT treat the response as a receipt worth acting on. There is no
// retry contract here by design — see AddFlow on why a re-delivered batch double-counts.
func (srv *server) ingestFlow(w http.ResponseWriter, r *http.Request) {
	var batch flowIngest
	if err := decodeCapped(r.Body, maxFlowBatchBytes, &batch); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			// #139: say WHICH failure. "invalid JSON body" for a valid batch that was
			// merely large points the sender at its encoder instead of at its batch size.
			log.Printf("flow: REFUSED a batch from %s: %v; capacity numbers will under-report that interval", r.RemoteAddr, err)
			http.Error(w, fmt.Sprintf("flow batch exceeds %d bytes", maxFlowBatchBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if batch.Instance == "" {
		// Without an instance we cannot tell replicas apart, and every row would collide
		// on the same primary key — silently summing several firewalls into one identity.
		// Better to refuse than to corrupt the dataset with an unattributable batch.
		http.Error(w, "instance is required", http.StatusBadRequest)
		return
	}

	// Stamp the instance server-side from the batch envelope rather than trusting a
	// per-row value, so one batch can never write rows attributed to another replica.
	// Kind is normalized here too: an unknown kind from a newer firewall is filed under
	// "infra" rather than rejected, because losing the whole batch would be the worse
	// failure for best-effort telemetry.
	for i := range batch.Packages {
		batch.Packages[i].Instance = batch.Instance
		batch.Packages[i].Kind = normalizeFlowKind(batch.Packages[i].Kind)
	}
	for i := range batch.Sources {
		batch.Sources[i].Instance = batch.Instance
	}

	if err := srv.store.AddFlow(batch.Packages, batch.Sources); err != nil {
		log.Printf("flow ingest from %q: %v", batch.Instance, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// parseFlowFilter reads the shared query parameters. Bad input is an error, never a
// silently-ignored parameter: a dashboard showing an unfiltered window while the operator
// believes it is scoped is the same class of lie as an unfiltered audit search that looks
// filtered (the guard A1 established).
func parseFlowFilter(r *http.Request) (FlowFilter, error) {
	q := r.URL.Query()
	f := FlowFilter{Ecosystem: q.Get("ecosystem"), Instance: q.Get("instance")}
	parse := func(name string) (time.Time, error) {
		v := q.Get(name)
		if v == "" {
			return time.Time{}, nil
		}
		t, err := time.Parse(time.RFC3339, v)
		return t.UTC(), err
	}
	var err error
	if f.From, err = parse("from"); err != nil {
		return f, err
	}
	if f.To, err = parse("to"); err != nil {
		return f, err
	}
	return f, nil
}

// parseLimit reads ?limit. Absent means the ranking's own default; an explicit 0 means
// "no limit" so a caller can always reconcile a ranking against the summary total.
func parseLimit(r *http.Request, def int) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, errBadLimit
	}
	return n, nil
}

type flowError string

func (e flowError) Error() string { return string(e) }

const errBadLimit = flowError("limit must be a non-negative integer")

// defaultFlowTopN bounds a ranking when the caller does not ask for a size. Chosen to
// fill a dashboard panel without paging; ?limit=0 lifts it entirely.
const defaultFlowTopN = 25

func (srv *server) flowSummary(w http.ResponseWriter, r *http.Request) {
	f, err := parseFlowFilter(r)
	if err != nil {
		http.Error(w, "from/to must be RFC3339 timestamps", http.StatusBadRequest)
		return
	}
	sum, err := srv.store.FlowSummary(f)
	if err != nil {
		log.Printf("flow summary: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (srv *server) flowPackages(w http.ResponseWriter, r *http.Request) {
	f, err := parseFlowFilter(r)
	if err != nil {
		http.Error(w, "from/to must be RFC3339 timestamps", http.StatusBadRequest)
		return
	}
	limit, err := parseLimit(r, defaultFlowTopN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, err := srv.store.FlowTopPackages(f, limit)
	if err != nil {
		log.Printf("flow packages: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (srv *server) flowSources(w http.ResponseWriter, r *http.Request) {
	f, err := parseFlowFilter(r)
	if err != nil {
		http.Error(w, "from/to must be RFC3339 timestamps", http.StatusBadRequest)
		return
	}
	limit, err := parseLimit(r, defaultFlowTopN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rows, err := srv.store.FlowTopSources(f, limit)
	if err != nil {
		log.Printf("flow sources: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// maxSeriesPoints bounds how many steps one series response may contain.
//
// This is a real guard, not a formality: ?from=2020&step=1s asks for ~200 million points
// and would build that slice in memory before writing a byte. The series is gap-filled,
// so the cost is driven by the WINDOW and STEP the caller chose, not by how much traffic
// actually happened — which is exactly the shape that turns a dashboard link into an
// accidental self-DoS.
const maxSeriesPoints = 5000

func (srv *server) flowSeries(w http.ResponseWriter, r *http.Request) {
	f, err := parseFlowFilter(r)
	if err != nil {
		http.Error(w, "from/to must be RFC3339 timestamps", http.StatusBadRequest)
		return
	}
	step := time.Minute
	if v := r.URL.Query().Get("step"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			http.Error(w, "step must be a positive duration (e.g. 1m, 15m, 1h)", http.StatusBadRequest)
			return
		}
		step = d
	}
	// Refuse an over-wide request rather than quietly coarsening the step: silently
	// changing the resolution would make the chart's x-axis disagree with what was asked
	// for, and the caller could not tell.
	if !f.From.IsZero() && !f.To.IsZero() {
		if n := f.To.Sub(f.From) / step; n > maxSeriesPoints {
			http.Error(w, "window/step would exceed "+strconv.Itoa(maxSeriesPoints)+" points; widen step or narrow the window", http.StatusBadRequest)
			return
		}
	}

	pts, err := srv.store.FlowSeries(f, step)
	if err != nil {
		log.Printf("flow series: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, pts)
}

// startFlowRetention runs the retention sweep on an interval until ctx-free shutdown.
//
// Retention is UNIFORM and operator-configurable (D88): one duration, no tier check
// anywhere in this path. The ruling: "the only limit to retention is how big your hard drive
// is as the customer, and if I bill you for that also you will be incensed."
//
// A retention of 0 disables the sweep entirely — the operator keeps everything and
// manages their own disk. That is a legitimate choice for a self-hosted deployment and
// must not be second-guessed by a hidden ceiling.
func startFlowRetention(store Store, retention, every time.Duration) {
	if retention <= 0 {
		log.Printf("flow retention: disabled (keeping all history)")
		return
	}
	if every <= 0 {
		every = time.Hour
	}
	log.Printf("flow retention: keeping %s of history, sweeping every %s", retention, every)
	go func() {
		// Sweep once at startup so a restart after a long outage does not wait a full
		// interval before reclaiming space.
		for {
			cutoff := time.Now().UTC().Add(-retention)
			n, err := store.PurgeFlowBefore(cutoff)
			if err != nil {
				// Log and keep going: failing to prune is a disk problem to alert on, never
				// a reason to take the control plane down.
				log.Printf("flow retention sweep: %v", err)
			} else if n > 0 {
				log.Printf("flow retention: purged %d rows older than %s", n, cutoff.Format(time.RFC3339))
			}
			time.Sleep(every)
		}
	}()
}
