package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// The approval service is Yellow Jack's stateful control plane: a separate
// microservice (its own binary, its own port, HTTP/REST) that records human
// decisions about packages the firewall cannot score automatically. Keeping it
// separate is deliberate — the firewall stays stateless and horizontally
// scalable, while this one service owns the durable state.
func main() {
	addr := getEnv("APPROVAL_LISTEN_ADDR", ":8090")

	// Choose the storage backend from config. A database URL => durable Postgres;
	// empty => in-memory (handy for local dev, but lost on restart).
	var st Store
	if dsn := getEnv("APPROVAL_DATABASE_URL", ""); dsn != "" {
		pg, err := newPGStore(dsn)
		if err != nil {
			log.Fatalf("database init failed: %v", err)
		}
		st = pg
		log.Printf("Yellow Jack approval service: storage=postgres")
	} else {
		st = newMemStore()
		log.Printf("Yellow Jack approval service: storage=in-memory (set APPROVAL_DATABASE_URL to persist)")
	}

	// APPROVAL_UPSTREAM_ECOSYSTEM names which protocol to speak; empty (the default)
	// means no harvest and no outbound call. Two variables rather than one because
	// the base URL is the thing an air-gapped or mirrored deployment must override,
	// and conflating "which protocol" with "which host" would make that override
	// carry a meaning it should not.
	srv := &server{store: st, upstream: newUpstreamFetcher(getEnv("APPROVAL_UPSTREAM_ECOSYSTEM", "npm")), fpForwarder: newFPForwarder()}
	if srv.fpForwarder == nil {
		log.Printf("false-positive reports: recorded locally only (APPROVAL_FP_WEBHOOK is empty; no report leaves this service)")
	} else {
		log.Printf("false-positive reports: recorded locally AND forwarded to the operator-configured destination")
	}

	// Flow-telemetry retention (#32 Phase C). UNIFORM for every deployment and
	// operator-configurable — there is deliberately no tier check here and must never be
	// one (D88): the history sits on the customer's own disk, which they already paid
	// for. APPROVAL_FLOW_RETENTION=0 disables the sweep and keeps everything, which is a
	// legitimate choice for a self-hosted operator managing their own storage.
	startFlowRetention(st,
		getEnvDuration("APPROVAL_FLOW_RETENTION", 14*24*time.Hour),
		getEnvDuration("APPROVAL_FLOW_SWEEP_INTERVAL", time.Hour))

	// Alert email (#32 Phase C / C4c, D90). Off unless the operator points us at their own
	// relay — we never host or route the mail (D52). A BROKEN mail config is fatal at
	// startup, unlike the retention duration above which merely warns: a typo there costs
	// a sub-optimal sweep interval, whereas a typo here means the operator believes they
	// will be told about outages and will not be. Failing to boot is the only way that
	// mistake is discovered before it matters. Alerts remain readable at GET /v1/alerts
	// whether or not email is configured — email is a delivery channel, not the feature.
	smtpCfg, err := loadSMTPConfig()
	if err != nil {
		log.Fatalf("alert email config: %v", err)
	}
	var sender mailSender
	if smtpCfg != nil {
		sender = &smtpSender{cfg: smtpCfg}
	}
	startAlertNotifier(st, sender, getEnvDuration("APPROVAL_ALERT_SWEEP_INTERVAL", time.Minute))

	log.Printf("Yellow Jack approval service starting on %s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("approval service failed: %v", err)
	}
}

// getEnvDuration reads a Go duration ("14d" is not valid Go — use "336h"). A malformed
// value falls back to the default WITH a loud warning rather than failing startup: the
// control plane refusing to boot over a telemetry-retention typo would take the gate
// down for a non-gate reason.
func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("WARNING: %s=%q is not a valid duration (e.g. 336h, 90m); using %s", key, v, fallback)
		return fallback
	}
	return d
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// server holds the dependencies for the HTTP handlers. It depends on the Store
// interface, not a concrete type, so the backend (memory/Postgres) is swappable.
type server struct {
	store Store
	// upstream harvests the registry's own metadata for the developer lookup (D158).
	// NIL IS THE SHIPPED DEFAULT and means "not configured": no outbound call is made
	// and /v1/packages reports the field as not collected, exactly as before. See
	// approval/upstream.go for why it is opt-in rather than defaulted to npmjs.org.
	upstream upstreamFetcher
	// fpForwarder posts false-positive reports to an operator-named destination (#142).
	// NIL IS THE SHIPPED DEFAULT and means no outbound call is ever made for a report.
	fpForwarder *fpForwarder
}

// ServeHTTP routes the small REST surface:
//
//	GET  /healthz                      -> liveness
//	GET  /v1/decisions                 -> list all decisions
//	GET  /v1/decisions?package=NAME    -> fetch one (404 if none recorded)
//	PUT  /v1/decisions                 -> upsert a decision (JSON body)
//	GET  /v1/packages?package=NAME     -> aggregate read-only status for one package
//	GET    /v1/scores?repo=REPO        -> fetch a cached score (404 if never scanned)
//	PUT    /v1/scores                  -> upsert a cached score (JSON body; L2, D18)
//	DELETE /v1/scores?repo=REPO        -> clear a cached score -> forces a re-scan (#12)
//	POST /v1/flow                      -> ingest pre-aggregated traffic counters (#32 C2)
//	GET  /v1/flow/{summary,packages,sources,series} -> the capacity reads (D81)
func (srv *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
		return
	}
	switch r.URL.Path {
	case "/v1/decisions":
		switch r.Method {
		case http.MethodGet:
			if pkg := r.URL.Query().Get("package"); pkg != "" {
				srv.getDecision(w, pkg)
			} else {
				srv.listDecisions(w)
			}
		case http.MethodPut:
			srv.putDecision(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/packages":
		// Read-only aggregate status for one package (D135 pillar 4 / D137 CLI dry-run
		// / D139 stop-gap). GET only, and deliberately so: D140 ruled that an
		// unauthenticated caller must not be able to start work that costs compute.
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.getPackageStatus(w, r)
	case "/v1/scores":
		switch r.Method {
		case http.MethodGet:
			srv.getScore(w, r.URL.Query().Get("repo"))
		case http.MethodPut:
			srv.putScore(w, r)
		case http.MethodDelete:
			srv.deleteScore(w, r.URL.Query().Get("repo"))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/events":
		// POST appends (events are CREATED, never replaced — so POST, not the
		// upsert PUT the other resources use); GET lists newest-first. There is no
		// PUT/DELETE here on purpose: the audit log is append-only.
		switch r.Method {
		case http.MethodGet:
			srv.listEvents(w, r)
		case http.MethodPost:
			srv.appendEvent(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/events/export":
		// The complete decision-log export (#28), NDJSON, oldest-first, no limit.
		// Distinct path from /v1/events because it is a different contract: the list is
		// bounded for a UI; the export is complete for an auditor.
		switch r.Method {
		case http.MethodGet:
			srv.exportEvents(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/events/summary":
		// The at-a-glance tally for the console's Overview: allowed / refused / served
		// anyway since ?since= (default: the last 24 hours). Complete, not windowed.
		switch r.Method {
		case http.MethodGet:
			srv.summarizeEvents(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/events/last-seen":
		// The per-package last-activity aggregation (#32 Phase C, D81 Q3): "what has
		// this firewall seen, and what has gone quiet". Same filters, also COMPLETE —
		// the quiet package is by definition the one a recency window would drop.
		switch r.Method {
		case http.MethodGet:
			srv.lastSeenByPackage(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/alerts":
		// The default alert set (#32 Phase C / C4b), computed on read from live data.
		// GET only: alerts are derived, not stored, so there is nothing to write.
		switch r.Method {
		case http.MethodGet:
			srv.listAlerts(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/health":
		// Per-replica heartbeat (#32 Phase C / C4a). POST reports, GET lists.
		// Distinct from /healthz above, which is THIS service's own liveness for an
		// orchestrator; this one is the FIREWALL replicas reporting to us, and it is
		// what lets an operator tell a dead firewall from an idle one.
		switch r.Method {
		case http.MethodPost:
			srv.ingestHealth(w, r)
		case http.MethodGet:
			srv.listHealth(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/flow":
		// Ingest from the firewall. POST only: these are counters being ADDED, never a
		// resource being replaced, so there is no PUT here for the same reason the audit
		// log has none.
		switch r.Method {
		case http.MethodPost:
			srv.ingestFlow(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/v1/flow/summary", "/v1/flow/packages", "/v1/flow/sources", "/v1/flow/series":
		// The four capacity reads (D81 Q1/Q2/Q4). Grouped because they share the same
		// filter contract and the same method guard; the dispatch below keeps each
		// handler's own concerns separate.
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/v1/flow/summary":
			srv.flowSummary(w, r)
		case "/v1/flow/packages":
			srv.flowPackages(w, r)
		case "/v1/flow/sources":
			srv.flowSources(w, r)
		default:
			srv.flowSeries(w, r)
		}
	case "/v1/false-positives":
		srv.handleFalsePositives(w, r)
	case "/v1/events/by-ip":
		// The downloads-by-source-IP aggregation (#41): "who pulled this package, how
		// often". Same ?ecosystem/?action/?package filters as the list, but a COMPLETE
		// count (no limit) — a partial count is a wrong count for incident response.
		switch r.Method {
		case http.MethodGet:
			srv.downloadsByIP(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}

func (srv *server) getDecision(w http.ResponseWriter, pkg string) {
	d, ok, err := srv.store.Get(pkg)
	if err != nil {
		log.Printf("get %q: %v", pkg, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no decision recorded for package", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (srv *server) listDecisions(w http.ResponseWriter) {
	ds, err := srv.store.List()
	if err != nil {
		log.Printf("list: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

func (srv *server) putDecision(w http.ResponseWriter, r *http.Request) {
	var d Decision
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if d.Package == "" {
		http.Error(w, "package is required", http.StatusBadRequest)
		return
	}
	if d.Verdict == "" {
		d.Verdict = VerdictPending
	}
	saved, err := srv.store.Put(d)
	if err != nil {
		log.Printf("put %q: %v", d.Package, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	log.Printf("decision recorded: %s -> %s (by %q)", saved.Package, saved.Verdict, saved.DecidedBy)
	writeJSON(w, http.StatusOK, saved)
}

func (srv *server) getScore(w http.ResponseWriter, repo string) {
	if repo == "" {
		http.Error(w, "repo is required", http.StatusBadRequest)
		return
	}
	rec, ok, err := srv.store.GetScore(repo)
	if err != nil {
		log.Printf("get score %q: %v", repo, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !ok {
		// Never scanned. 404 mirrors the decisions endpoint: the firewall reads
		// this as "cold" and launches a background scan.
		http.Error(w, "no score cached for repo", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (srv *server) putScore(w http.ResponseWriter, r *http.Request) {
	var rec ScoreRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if rec.Repo == "" {
		http.Error(w, "repo is required", http.StatusBadRequest)
		return
	}
	saved, err := srv.store.PutScore(rec)
	if err != nil {
		log.Printf("put score %q: %v", rec.Repo, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// A nil Score is the negative "scanned-but-unscorable" marker; log both shapes.
	if saved.Score != nil {
		log.Printf("score cached: %s -> %.1f", saved.Repo, *saved.Score)
	} else {
		log.Printf("score cached: %s -> unscorable", saved.Repo)
	}
	writeJSON(w, http.StatusOK, saved)
}

// deleteScore clears a repo's cached L2 score (DELETE /v1/scores?repo=REPO). This is
// the operator-triggered re-scan primitive for issue #12: once the row is gone the
// next pull sees a cold repo and the firewall launches a fresh background scan. 204
// on a real delete, 404 when there was nothing to clear (so the caller knows the
// repo name matched no row rather than assuming a re-scan was queued).
func (srv *server) deleteScore(w http.ResponseWriter, repo string) {
	if repo == "" {
		http.Error(w, "repo is required", http.StatusBadRequest)
		return
	}
	existed, err := srv.store.DeleteScore(repo)
	if err != nil {
		log.Printf("delete score %q: %v", repo, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !existed {
		http.Error(w, "no score cached for repo", http.StatusNotFound)
		return
	}
	log.Printf("score cleared (re-scan forced): %s", repo)
	w.WriteHeader(http.StatusNoContent)
}

// appendEvent records one immutable audit event (POST /v1/events). It requires a
// package and one of the two known actions; an unknown action is a 400 so a
// malformed emitter can't pollute the trail with garbage verdicts. On success it
// returns 201 Created with the stored event (now carrying its assigned id).
func (srv *server) appendEvent(w http.ResponseWriter, r *http.Request) {
	var e AuditEvent
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if e.Package == "" {
		http.Error(w, "package is required", http.StatusBadRequest)
		return
	}
	if e.Action != ActionAllow && e.Action != ActionBlock {
		http.Error(w, "action must be allow or block", http.StatusBadRequest)
		return
	}
	saved, err := srv.store.AppendEvent(e)
	if err != nil {
		log.Printf("append event %q: %v", e.Package, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

// listEvents returns the most recent audit events (GET /v1/events), optionally
// narrowed by the incident-response filters ?ecosystem=, ?action=, ?package=. The
// limit defaults to defaultEventLimit and is clamped to maxEventLimit, so a client
// can never ask the store for an unbounded result set.
func (srv *server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := defaultEventLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxEventLimit {
		limit = maxEventLimit
	}

	f := EventFilter{
		Ecosystem: q.Get("ecosystem"),
		Package:   q.Get("package"),
		Limit:     limit,
	}
	// A present action filter must be a known action. Silently ignoring a typo like
	// ?action=blocked would return unfiltered results that LOOK filtered — worse than
	// an error for someone scoping an incident. So reject it with a 400.
	if a := q.Get("action"); a != "" {
		if a != string(ActionAllow) && a != string(ActionBlock) {
			http.Error(w, "action must be allow or block", http.StatusBadRequest)
			return
		}
		f.Action = AuditAction(a)
	}

	events, err := srv.store.ListEvents(f)
	if err != nil {
		log.Printf("list events: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// exportEvents streams the COMPLETE decision log as NDJSON (one JSON event per line),
// oldest-first, for the compliance/due-diligence record (#28). It honours the same
// ?ecosystem/?action/?package filters as the list (so an operator can export a scoped
// incident set) but deliberately has no limit — the export's whole value is that it is
// complete. json.Encoder.Encode writes each value followed by a newline, which is
// exactly NDJSON, and StreamEvents feeds it row-by-row so a large log never buffers.
//
// The schema is PROVISIONAL (version=0) and this comment is maintained rather than
// left to rot, because a contract sentence that quietly stops being true is worse
// than one that never was. It carries: package, ecosystem, action, score, reason,
// source_ip, at, threshold, policy_digest.
//
// threshold and policy_digest are #28's "the inputs that produced it", added because
// score+reason alone are not reproducible — a reader months later cannot tell whether
// score 4.2 failed a bar of 5.0 or whether the block came from elsewhere entirely.
// With both present the verdict is checkable from a single exported line.
//
// STILL MISSING from #28's list, so this must not be presented as a completed
// compliance artifact:
//   - the resolved VERSION. Only some ecosystems put it in the request identity (OCI
//     does, an npm packument request does not), so it is not a field that can simply
//     be added — it needs a per-ecosystem answer.
//   - cache-served. D151 removed the cache from scope permanently, so unless the
//     integration with the customer's registry surfaces it, this one has no source
//     and should be dropped from #28 rather than left looking outstanding.
//
// It remains the authoritative record of what was pulled and why: an input to a
// due-diligence file, not a conformance claim.
func (srv *server) exportEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := EventFilter{
		Ecosystem: q.Get("ecosystem"),
		Package:   q.Get("package"),
	}
	if a := q.Get("action"); a != "" {
		if a != string(ActionAllow) && a != string(ActionBlock) {
			http.Error(w, "action must be allow or block", http.StatusBadRequest)
			return
		}
		f.Action = AuditAction(a)
	}

	enc := json.NewEncoder(w)
	wrote := false
	setHeaders := func() {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("X-Yellowjack-Schema", "decision-log; version=0-provisional")
	}
	err := srv.store.StreamEvents(f, func(e AuditEvent) error {
		if !wrote {
			// Set headers before the first byte. Doing it inside the callback (not
			// eagerly before StreamEvents) means a storage error that fails BEFORE any
			// row can still become a clean 500 below, rather than a misleading empty-
			// but-200 body — which for a compliance export would read as "nothing was
			// pulled", the wrong and dangerous conclusion.
			setHeaders()
			wrote = true
		}
		return enc.Encode(e)
	})
	if err != nil {
		if !wrote {
			log.Printf("export events: %v", err)
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		// Mid-stream failure (e.g. client disconnected): status is already sent, so we
		// can only log. The partial body is truncated, which a caller detects via the
		// dropped connection — better than pretending success.
		log.Printf("export events (mid-stream): %v", err)
		return
	}
	if !wrote {
		// Zero events matched: still a valid, empty NDJSON 200 with the same headers,
		// so a caller gets a well-formed (empty) document rather than an error.
		setHeaders()
		w.WriteHeader(http.StatusOK)
	}
}

// downloadsByIP returns the per-source-IP download tally for a scoped set of pulls
// (GET /v1/events/by-ip), the "who pulled this package, how often" incident-response
// query (#41, D83). It honours the same ?ecosystem/?action/?package filters as the
// list but has NO limit: unlike the bounded list, the count must be COMPLETE, because
// a truncated count is a wrong count. Rows come back most-frequent-first.
func (srv *server) downloadsByIP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := EventFilter{
		Ecosystem: q.Get("ecosystem"),
		Package:   q.Get("package"),
	}
	// Same guard as the list: a typo'd action must 400, not silently return an
	// unfiltered-but-filtered-looking tally to someone scoping an incident.
	if a := q.Get("action"); a != "" {
		if a != string(ActionAllow) && a != string(ActionBlock) {
			http.Error(w, "action must be allow or block", http.StatusBadRequest)
			return
		}
		f.Action = AuditAction(a)
	}

	rows, err := srv.store.DownloadsByIP(f)
	if err != nil {
		log.Printf("downloads by ip: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// lastSeenByPackage returns per-package activity for a scoped set of events (GET
// /v1/events/last-seen), quietest first — the observed-flow half of D81 Q3 ("how many
// packages are stale"). Same ?ecosystem/?action/?package filters, and like the by-ip
// tally it is COMPLETE rather than windowed, because the package that went quiet
// longest ago is exactly the one a recency window drops.
//
// The caller chooses what "seen" means via ?action: allow = last successfully pulled,
// omitted = any terminal verdict. The console asks for allow (see its staleness view) —
// a package blocked daily would otherwise look freshly used.
func (srv *server) lastSeenByPackage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := EventFilter{
		Ecosystem: q.Get("ecosystem"),
		Package:   q.Get("package"),
	}
	// Same guard as the list and the by-ip tally: a typo'd action must 400 rather than
	// return an unfiltered result that looks filtered.
	if a := q.Get("action"); a != "" {
		if a != string(ActionAllow) && a != string(ActionBlock) {
			http.Error(w, "action must be allow or block", http.StatusBadRequest)
			return
		}
		f.Action = AuditAction(a)
	}

	rows, err := srv.store.LastSeenByPackage(f)
	if err != nil {
		log.Printf("last seen by package: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// defaultSummaryWindow is the window /v1/events/summary covers when ?since= is absent.
// "The last 24 hours" rather than "today", because today begins at a different instant
// in every operator's timezone and the control plane cannot know which one is asking.
const defaultSummaryWindow = 24 * time.Hour

// summarizeEvents returns the verdict tally since ?since= (GET /v1/events/summary). A
// since that is not RFC3339 is a 400: silently falling back to the default would hand
// back a tally for a window the caller did not ask for, labelled as the one they did.
func (srv *server) summarizeEvents(w http.ResponseWriter, r *http.Request) {
	since := time.Now().UTC().Add(-defaultSummaryWindow)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "since must be an RFC3339 timestamp", http.StatusBadRequest)
			return
		}
		since = t
	}
	sum, err := srv.store.SummarizeEvents(since)
	if err != nil {
		log.Printf("summarize events: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// writeJSON is a small helper so every handler emits consistent JSON responses.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
