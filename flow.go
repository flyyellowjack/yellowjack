package main

import (
	"sort"
	"sync"
)

// Flow accounting: how much traffic moved through this firewall, for which package,
// and what went wrong (#32 Phase C, D80/D81).
//
// This is the DATA SOURCE the capacity dashboard was missing. The audit log cannot be
// it, for three independent reasons recorded in docs/CAPACITY_INSTRUMENTATION.md §4.1 —
// the short version being that it is one event per terminal VERDICT, while bytes move
// on many responses per package and also on paths that have no verdict at all (ungated
// registry-infrastructure relays, artifact byte fetches, refused paths). Keeping the two
// separate is what preserves the one-event-per-verdict invariant the #28 compliance
// export depends on.
//
// This file is the in-process half: counters, safe under the per-request goroutines.
// Shipping them to a durable sink is the NEXT increment and is deliberately not here.

// flowKind classifies what a relayed response carried. It matters because "this package
// moved 4 GB" reads very differently depending on whether that was one artifact download
// or a million packument refreshes, and an operator chasing a saturated pipe needs to
// tell those apart.
type flowKind string

const (
	flowMetadata flowKind = "metadata" // packuments, /simple/ indexes, OCI manifests, POMs
	flowArtifact flowKind = "artifact" // tarballs, wheels/sdists, OCI blobs — the opaque bytes
	flowInfra    flowKind = "infra"    // registry plumbing with no package identity (see flowID)
	// flowWrite is bytes going the OTHER WAY — a push an operator opted into relaying
	// via FW_WRITE_POLICY. Kept distinct because #66 item 3 is a real accounting bug,
	// not a labelling nicety: recorded as flowArtifact, an upload adds to the same
	// counter as a download, so the capacity dashboard reads bytes we SENT as bytes we
	// SERVED. The two have opposite signs from the operator's point of view.
	flowWrite flowKind = "write"
)

// flowID says whose traffic a single relay belongs to. It is threaded from the request
// handlers — which know the authoritative package name because they just gated on it —
// down into relay, which historically knew only a target URL.
//
// An EMPTY Package is legitimate and must stay countable: registry infrastructure
// requests (OCI's /v2/ handshake, token endpoints, a registry ping) carry no package
// identity but do carry bytes. They are recorded under the empty name, exactly as the
// downloads-by-IP view keeps an "(unobserved)" bucket, so that per-package rows still
// SUM TO THE INSTANCE TOTAL. Dropping them would make the dashboard's own arithmetic
// disagree with itself, which is worse than a missing row because it is invisible.
type flowID struct {
	Package string
	Kind    flowKind
}

// flowKey is the aggregation key. Ecosystem is on the key rather than implied by the
// process because the counters are destined for a shared control plane where one row
// must still say which firewall it came from — and because "requests" means a different
// package in npm than in pypi.
type flowKey struct {
	Ecosystem string
	Package   string
	Kind      flowKind
}

// flowCounts are the per-key totals. All monotonic: this is a counter set, never a
// gauge — a rate is derived at read time by differencing over a window, never stored,
// because a stored rate is wrong the moment the window changes.
type flowCounts struct {
	Requests int64
	// Two byte counters, not one, because they genuinely differ: metadata is rewritten
	// on the way through (artifact URLs are pointed back at us), so what we pulled from
	// upstream and what we served the developer are different sizes. BytesUpstream is
	// the number an egress-metered site cares about — it is what crossed their internet
	// link; BytesClient is the LAN/serving side.
	BytesUpstream int64
	BytesClient   int64

	// Failure accounting (D81 Q5). These are TRANSPORT-level failures, with ONE
	// exception now, and the exception is narrow on purpose.
	//
	// This block used to say we never hash artifact bodies, so a corrupt-but-complete
	// file was invisible and nothing here could honestly be called "corruption". That
	// is still true of npm, and of any artifact fetched by HEAD, by Range or with a
	// Content-Encoding. It is NO LONGER true of a whole OCI blob (the digest is in its
	// URL), of a PyPI file whose index this replica relayed (the digest is read off the
	// index), or of a Maven file whose repository sent a checksum header: #64
	// hashes those bytes as they stream and IntegrityMismatches counts the ones that
	// did not sum to what was published.
	//
	// Keep the distinction when reading these numbers. Everything but the last line is
	// "the transfer broke"; the last line is "the transfer completed and the bytes were
	// wrong", which is a different event with a different cause and a different person
	// to call.
	Truncated           int64 // upstream delivered fewer bytes than it promised
	RelayErrors         int64 // copy failed for a reason that was not a short body
	TransportErrors     int64 // upstream unreachable after the retry budget
	UpstreamStatus      int64 // upstream answered with a status that is a real failure (see recordStatus)
	MetaErrors          int64 // metadata unreadable or too large to relay
	Retries             int64 // transport retries attempted — a leading indicator, not itself a failure
	IntegrityMismatches int64 // a complete OCI blob or PyPI file whose bytes did not match its published digest (#64)
}

// flowRow is one snapshot row: a key and its totals.
type flowRow struct {
	flowKey
	flowCounts
}

// flowRecorder accumulates the counters in memory. It is written from every per-request
// goroutine, so every access takes the mutex. A mutex rather than atomics per field
// because a relay updates several counters that should move together, and because the
// contention is trivial next to the network I/O each caller just did.
//
// A nil *flowRecorder is a valid no-op recorder — every method checks — so tests and any
// future build that wires no accounting still run unchanged. Same idiom as auditEmitter.
type flowRecorder struct {
	ecosystem string

	mu     sync.Mutex
	counts map[flowKey]*flowCounts
	// ipCounts is the SECOND, deliberately separate aggregation (D92): bytes by source
	// IP, answering "which host is consuming the pipe". It is a sibling map rather than
	// an extra field on flowKey because joining the two dimensions would make the key a
	// CROSS PRODUCT — distinct packages x distinct IPs — which is the one thing here
	// that grows multiplicatively. The joint question is already answered completely by
	// the audit log's DownloadsByIP, so this side stays marginal on purpose.
	ipCounts map[flowIPKey]*flowIPCounts
}

// flowIPKey / flowIPCounts: the marginal per-source-IP totals. Fewer counters than the
// package side because the failure taxonomy is a property of a RELAY, not of a host —
// attributing an upstream truncation to the developer who happened to request it would
// read as "this host is causing corruption", which is the wrong story.
type flowIPKey struct {
	Ecosystem string
	SourceIP  string
}

type flowIPCounts struct {
	Requests      int64
	BytesUpstream int64
	BytesClient   int64
}

func newFlowRecorder(ecosystem string) *flowRecorder {
	return &flowRecorder{
		ecosystem: ecosystem,
		counts:    make(map[flowKey]*flowCounts),
		ipCounts:  make(map[flowIPKey]*flowIPCounts),
	}
}

// withIP runs fn against the per-IP counters, creating them on first use. An EMPTY ip is
// kept, not dropped: an unattributable pull still moved bytes, and losing it would make
// the per-host view disagree with the per-package total for the same traffic.
func (f *flowRecorder) withIP(ip string, fn func(*flowIPCounts)) {
	if f == nil {
		return
	}
	k := flowIPKey{Ecosystem: f.ecosystem, SourceIP: ip}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.ipCounts[k]
	if c == nil {
		c = &flowIPCounts{}
		f.ipCounts[k] = c
	}
	fn(c)
}

// recordIPRequest / recordIPBytes mirror the package-side calls. They are separate calls
// rather than folded into recordRequest/recordBytes so the two aggregations stay visibly
// independent at every call site — it should be obvious in relay that two different
// datasets are being written, not one.
func (f *flowRecorder) recordIPRequest(ip string) {
	f.withIP(ip, func(c *flowIPCounts) { c.Requests++ })
}

func (f *flowRecorder) recordIPBytes(ip string, upstream, client int64) {
	f.withIP(ip, func(c *flowIPCounts) {
		c.BytesUpstream += upstream
		c.BytesClient += client
	})
}

// with runs fn against the counter set for id, creating it on first use.
func (f *flowRecorder) with(id flowID, fn func(*flowCounts)) {
	if f == nil {
		return
	}
	k := flowKey{Ecosystem: f.ecosystem, Package: id.Package, Kind: id.Kind}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.counts[k]
	if c == nil {
		c = &flowCounts{}
		f.counts[k] = c
	}
	fn(c)
}

// recordRequest counts one relayed request, whatever its outcome.
func (f *flowRecorder) recordRequest(id flowID) {
	f.with(id, func(c *flowCounts) { c.Requests++ })
}

// recordBytes counts bytes that ACTUALLY MOVED.
//
// The trap this exists to avoid: the obvious implementation reads Content-Length, which
// is what upstream PROMISED. Those agree right up until the moment something breaks —
// so counting the header would inflate the numbers precisely during the incident the
// dashboard is there to explain, and a truncated 400 MB blob would be reported as a
// healthy 400 MB of traffic. Callers pass io.Copy's return value.
func (f *flowRecorder) recordBytes(id flowID, upstream, client int64) {
	f.with(id, func(c *flowCounts) {
		c.BytesUpstream += upstream
		c.BytesClient += client
	})
}

// recordTruncated counts an upstream transfer that ended short of its promised length.
//
// CALLERS MUST NOT call this when the CLIENT hung up. A developer pressing Ctrl-C mid
// install produces a short read that looks identical here, and counting those would make
// the failure metric track developer impatience instead of upstream health — turning the
// zero-threshold alert into a permanent false alarm on day one. relay checks the request
// context before reaching this.
func (f *flowRecorder) recordTruncated(id flowID) {
	f.with(id, func(c *flowCounts) { c.Truncated++ })
}

func (f *flowRecorder) recordRelayError(id flowID) {
	f.with(id, func(c *flowCounts) { c.RelayErrors++ })
}

// recordIntegrityMismatch counts a COMPLETED artifact transfer whose bytes did not sum
// to the digest the request named (#64). Deliberately not folded into RelayErrors: that
// counter answers "did the transfer break", and this one answers "did we serve the wrong
// bytes" — an operator triaging a bad mirror needs to tell those apart at a glance, and
// a single number would make a CDN serving garbage look like a flaky link.
func (f *flowRecorder) recordIntegrityMismatch(id flowID) {
	f.with(id, func(c *flowCounts) { c.IntegrityMismatches++ })
}

func (f *flowRecorder) recordTransportError(id flowID) {
	f.with(id, func(c *flowCounts) { c.TransportErrors++ })
}

func (f *flowRecorder) recordMetaError(id flowID) {
	f.with(id, func(c *flowCounts) { c.MetaErrors++ })
}

func (f *flowRecorder) recordRetry(id flowID) {
	f.with(id, func(c *flowCounts) { c.Retries++ })
}

// recordStatus counts an upstream response status ONLY when it represents a real
// operational failure.
//
// Deliberately NOT every non-2xx. A 404 is routine and expected — package managers probe
// for optional artifacts (sources/javadoc jars, .asc signatures) and get 404s during
// perfectly healthy resolution, so counting them would make every dashboard show
// thousands of "failures" and train operators to ignore the number. What counts:
//   - 5xx — upstream is genuinely broken.
//   - 429 — upstream is rate-limiting us. A 4xx, but an operational problem the operator
//     must see; it is the whole subject of D25 and it silently degrades every pull.
func (f *flowRecorder) recordStatus(id flowID, status int) {
	if status < 500 && status != 429 {
		return
	}
	f.with(id, func(c *flowCounts) { c.UpstreamStatus++ })
}

// Snapshot returns a copy of every counter set, ordered for stable output. A copy, not
// the live maps, so a reader can never observe a half-updated row or race a writer.
func (f *flowRecorder) Snapshot() []flowRow {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	out := make([]flowRow, 0, len(f.counts))
	for k, c := range f.counts {
		out = append(out, flowRow{flowKey: k, flowCounts: *c})
	}
	f.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// flowIPRow is one snapshot row of the per-source-IP aggregation.
type flowIPRow struct {
	flowIPKey
	flowIPCounts
}

// SnapshotIPs returns a copy of the per-IP counters, ordered for stable output.
func (f *flowRecorder) SnapshotIPs() []flowIPRow {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	out := make([]flowIPRow, 0, len(f.ipCounts))
	for k, c := range f.ipCounts {
		out = append(out, flowIPRow{flowIPKey: k, flowIPCounts: *c})
	}
	f.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].SourceIP < out[j].SourceIP
	})
	return out
}

// Drain returns every counter set AND RESETS them, so what comes back is the traffic
// since the previous drain rather than a running total.
//
// The reset is the load-bearing half, and getting it wrong is silent: the sink adds each
// batch to what it already holds (the upsert is additive by necessity — replicas report
// independently). So if the recorder kept accumulating, every flush would re-send the
// running total and the stored numbers would grow QUADRATICALLY — a dashboard that looks
// plausible for the first few minutes and is wildly wrong by the end of the hour, with
// nothing failing anywhere. Snapshot (non-destructive) stays for gauges and tests; Drain
// is what the emitter uses.
//
// Taking both maps under one lock keeps the two aggregations consistent with each other:
// a relay counted in the package rows is counted in the IP rows of the SAME batch, never
// split across two.
func (f *flowRecorder) Drain() ([]flowRow, []flowIPRow) {
	if f == nil {
		return nil, nil
	}
	f.mu.Lock()
	pkgs := make([]flowRow, 0, len(f.counts))
	for k, c := range f.counts {
		pkgs = append(pkgs, flowRow{flowKey: k, flowCounts: *c})
	}
	ips := make([]flowIPRow, 0, len(f.ipCounts))
	for k, c := range f.ipCounts {
		ips = append(ips, flowIPRow{flowIPKey: k, flowIPCounts: *c})
	}
	// Fresh maps rather than clearing in place: a package seen once and never again
	// should stop occupying a key forever, otherwise a long-running firewall accumulates
	// one entry per package it has EVER served and the drain grows without bound.
	f.counts = make(map[flowKey]*flowCounts)
	f.ipCounts = make(map[flowIPKey]*flowIPCounts)
	f.mu.Unlock()

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Package != pkgs[j].Package {
			return pkgs[i].Package < pkgs[j].Package
		}
		return pkgs[i].Kind < pkgs[j].Kind
	})
	sort.Slice(ips, func(i, j int) bool { return ips[i].SourceIP < ips[j].SourceIP })
	return pkgs, ips
}

// recordRelay and recordRelayBytes update BOTH aggregations under a SINGLE lock.
//
// The reason they exist rather than the caller making two calls: Drain takes the same
// lock to snapshot both maps together, so if a relay updated the package map and the IP
// map in two separate acquisitions, a drain could land between them and split one
// response across two batches — its bytes counted against the package in one interval
// and against the source host in the next. The two datasets would then disagree for
// those intervals with nothing to explain it. One lock, one relay, one batch.
func (f *flowRecorder) recordRelay(id flowID, ip string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pkgLocked(id).Requests++
	f.ipLocked(ip).Requests++
}

func (f *flowRecorder) recordRelayBytes(id flowID, ip string, upstream, client int64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.pkgLocked(id)
	c.BytesUpstream += upstream
	c.BytesClient += client
	ic := f.ipLocked(ip)
	ic.BytesUpstream += upstream
	ic.BytesClient += client
}

// pkgLocked / ipLocked fetch-or-create a counter set. The caller MUST already hold mu —
// named so that reading a call site tells you the lock is held.
func (f *flowRecorder) pkgLocked(id flowID) *flowCounts {
	k := flowKey{Ecosystem: f.ecosystem, Package: id.Package, Kind: id.Kind}
	c := f.counts[k]
	if c == nil {
		c = &flowCounts{}
		f.counts[k] = c
	}
	return c
}

func (f *flowRecorder) ipLocked(ip string) *flowIPCounts {
	k := flowIPKey{Ecosystem: f.ecosystem, SourceIP: ip}
	c := f.ipCounts[k]
	if c == nil {
		c = &flowIPCounts{}
		f.ipCounts[k] = c
	}
	return c
}

// ecosystemName exposes the recorder's ecosystem for the heartbeat. A nil recorder
// reports "" rather than panicking, matching every other method here.
func (f *flowRecorder) ecosystemName() string {
	if f == nil {
		return ""
	}
	return f.ecosystem
}
