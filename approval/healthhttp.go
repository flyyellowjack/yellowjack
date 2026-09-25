package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// maxHealthBytes bounds one heartbeat body.
//
// Raised from 8 KiB when the beat began carrying the reported policy (#32 Phase D / D4).
// The shipped policy view measures ~1.2 KiB, so 8 KiB was not immediately tight — but the
// consequence of getting this wrong is severe and silent in the wrong direction: an
// oversized beat is REJECTED, the replica's reported_at stops advancing, and the control
// plane reads a perfectly healthy firewall as DEAD. A liveness signal lost to a
// policy-reporting feature is the worst possible trade, so the bound now has real headroom
// for a deployment that grows its ruleset. Still small enough to bound the allocation,
// which is what the limit is for.
const maxHealthBytes = 64 << 10

// healthIngest is the wire shape the firewall POSTs to /v1/health. Its own type rather
// than InstanceHealth so the REST boundary stays explicit (the same discipline the flow
// and audit DTOs follow), and so ReportedAt can be absent: the server sets it.
type healthIngest struct {
	Instance     string    `json:"instance"`
	Ecosystem    string    `json:"ecosystem,omitempty"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	AuditDropped int64     `json:"audit_dropped"`
	FlowDropped  int64     `json:"flow_dropped"`
	// Policy is accepted as RAW JSON and never decoded into a model of the policy — see
	// InstanceHealth.Policy for why this service deliberately does not understand it.
	Policy json.RawMessage `json:"policy,omitempty"`
}

// policyDigestOf pulls the digest out of a reported policy document.
//
// It decodes ONLY the digest and leaves everything else untouched, which is the whole
// point: the document is stored verbatim, and this service's understanding of it is
// limited to the one field it needs for comparison. A malformed or absent document yields
// an empty digest rather than an error — a replica whose policy report we cannot read is
// still a live replica whose heartbeat must land, and dropping the beat over an
// unparseable optional field would turn a reporting problem into a false outage.
func policyDigestOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var probe struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		log.Printf("health: policy report is not readable JSON; storing it verbatim without a digest: %v", err)
		return ""
	}
	return probe.Digest
}

// ingestHealth records one replica's heartbeat (POST /v1/health).
func (srv *server) ingestHealth(w http.ResponseWriter, r *http.Request) {
	var in healthIngest
	if err := decodeCapped(r.Body, maxHealthBytes, &in); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			// #139. This used to answer "invalid JSON body" for a perfectly valid beat
			// that was merely big -- and the consequence is the one the comment on
			// maxHealthBytes warns about: the replica's reported_at stops advancing and a
			// healthy firewall reads as DEAD. Measured: two 200-name operator lists of
			// ~160-character entries put the policy view alone over this cap. The body
			// could not be decoded, so the peer address is all the identity there is.
			log.Printf("health: REFUSED a heartbeat from %s: %v. That replica will read as STALE in the "+
				"console until its report shrinks; the firewall itself is unaffected", r.RemoteAddr, err)
			http.Error(w, fmt.Sprintf("heartbeat body exceeds %d bytes", maxHealthBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if in.Instance == "" {
		// Same reasoning as the flow ingest: without an identity every replica collides
		// on one primary key, and several firewalls would masquerade as a single
		// heartbeat — which would make a dead replica invisible behind a live one. That
		// is the exact failure this endpoint exists to catch, so refuse.
		http.Error(w, "instance is required", http.StatusBadRequest)
		return
	}

	h := InstanceHealth{
		Instance:  in.Instance,
		Ecosystem: in.Ecosystem,
		StartedAt: in.StartedAt,
		// ReportedAt is the SERVER's clock, deliberately not the client's. A replica with
		// a skewed clock would otherwise read as permanently stale or permanently fresh,
		// and an operator has no way to tell which. "Last seen 4m ago" has to be measured
		// against the clock the operator is looking at.
		ReportedAt:   time.Now().UTC(),
		AuditDropped: in.AuditDropped,
		FlowDropped:  in.FlowDropped,
		Policy:       in.Policy,
		PolicyDigest: policyDigestOf(in.Policy),
	}
	if err := srv.store.UpsertInstanceHealth(h); err != nil {
		log.Printf("upsert instance health: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// 202, matching the flow ingest: this is best-effort telemetry being accepted, not a
	// resource whose representation we are returning.
	w.WriteHeader(http.StatusAccepted)
}

// listHealth returns every replica that has reported (GET /v1/health), newest first.
//
// No staleness filter and no "healthy" boolean: the store returns the rows, the CALLER
// decides what counts as stale. Baking a threshold in here would put the alerting policy
// in the storage layer, where it could not be tuned or explained, and the console would
// have no way to show "last seen 9 minutes ago" for an instance the server had already
// judged and hidden.
func (srv *server) listHealth(w http.ResponseWriter, r *http.Request) {
	rows, err := srv.store.ListInstanceHealth()
	if err != nil {
		log.Printf("list instance health: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []InstanceHealth{} // [] not null, so a client can range over it unguarded
	}
	writeJSON(w, http.StatusOK, rows)
}
