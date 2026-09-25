package main

import (
	"fmt"
	"sort"
	"time"
)

// Default alerting for the capacity dashboard (#32 Phase C / C4b), per the project's
// 2026-07-27 note: metrics and alerting have to work with NO configuration, because
// "when you need it, you don't have time to set it up".
//
// EVERY ALERT HERE HAS A HEALTHY VALUE OF ZERO. That is the property that makes
// zero-config honest rather than a slogan: there is no threshold to pick, no baseline to
// learn, and no per-site tuning, because each condition is one an operator would call
// wrong at any volume. The moment an alert needs a number chosen for a particular
// deployment, it stops being shippable-by-default and belongs somewhere else.
//
// Deliberately NOT here: anything requiring a site-specific threshold ("bandwidth above
// X"), and the D82 "enforcement data is stale" alert — poll-and-cache is not built yet
// (Phase D), so there is no signal to read. Better an alert absent than an alert that
// silently never fires, which would read as "all clear" forever.

// AlertSeverity is deliberately two-valued. More levels invite an argument about which
// tier a condition belongs to, and an operator only really acts on two: something is
// broken now, or something is degrading and wants attention.
type AlertSeverity string

const (
	SeverityCritical AlertSeverity = "critical"
	SeverityWarning  AlertSeverity = "warning"
)

// Alert is one active condition. It carries its own explanation because the console and
// (later) the email both need to say WHY without re-deriving it, and because an alert an
// operator cannot act on is noise.
type Alert struct {
	// Kind is a stable machine identifier — safe to match on in tests and, later, to
	// deduplicate notifications by. The human text lives in Summary/Detail.
	Kind     string        `json:"kind"`
	Severity AlertSeverity `json:"severity"`
	// Instance is set when the condition belongs to one replica; empty when it is
	// deployment-wide.
	Instance string `json:"instance,omitempty"`
	Summary  string `json:"summary"`
	Detail   string `json:"detail"`
	// Since is when the condition became visible to us, so the console can say
	// "for the last 20 minutes" rather than just "now".
	Since time.Time `json:"since,omitempty"`
}

const (
	AlertInstanceSilent  = "instance_silent"
	AlertAuditDropping   = "audit_dropping"
	AlertMetricsDropping = "metrics_dropping"
	AlertTransferFailing = "transfer_failing"
)

// alertParams are the only knobs, and both have defaults that work unconfigured.
type alertParams struct {
	// SilentAfter is how long a replica may go without a heartbeat before it is called
	// silent. Generous relative to the firewall's default 1-minute flush: a missed beat
	// or two is a blip, and calling a firewall dead on one dropped packet is how an
	// alert earns a mute.
	SilentAfter time.Duration
	// Window is how far back transfer failures are counted.
	Window time.Duration
}

func defaultAlertParams() alertParams {
	return alertParams{SilentAfter: 15 * time.Minute, Window: time.Hour}
}

// evaluateAlerts is a PURE function: same inputs, same alerts, no clock of its own and no
// storage. Written this way on purpose —
//
//   - it can be tested exhaustively without a database or a fake clock;
//   - the read endpoint can call it directly, so what the console shows is always
//     computed from current data rather than from a sweep's possibly-stale opinion;
//   - and when C4c needs to know "have we already emailed about this?", it can call the
//     SAME function and diff the result against what it stored, rather than a second
//     implementation of the rules drifting away from this one.
//
// Persistence is deliberately absent until that notification-dedup need is real. Storing
// alert rows now would add a table, a sweep goroutine and a resolution lifecycle to
// support a feature nobody has asked this increment for.
func evaluateAlerts(now time.Time, health []InstanceHealth, window FlowSummary, p alertParams) []Alert {
	var out []Alert

	for _, h := range health {
		// A replica that has stopped reporting. THIS is the "is the firewall alive"
		// signal, and it is a heartbeat rather than an absence of traffic precisely
		// because an idle firewall and a dead one are indistinguishable in the flow data
		// (see InstanceHealth). Note it fires per instance: in a multi-replica
		// deployment the interesting case is one dead replica while the others carry the
		// load, which a deployment-wide check would miss entirely.
		if silent := now.Sub(h.ReportedAt); silent > p.SilentAfter {
			out = append(out, Alert{
				Kind:     AlertInstanceSilent,
				Severity: SeverityCritical,
				Instance: h.Instance,
				Summary:  fmt.Sprintf("Firewall %q has stopped reporting", h.Instance),
				Detail: fmt.Sprintf(
					"Last heartbeat %s ago (threshold %s). The instance may be stopped, wedged, or unable to reach the control plane. Package pulls through it are NOT necessarily failing — the gate keeps working without the control plane — but its traffic is no longer being recorded.",
					silent.Round(time.Second), p.SilentAfter),
				Since: h.ReportedAt,
			})
		}

		// "We know we lost data." Any non-zero value is wrong, which is what makes these
		// threshold-free. They are warnings rather than critical: the gate is unaffected
		// — what suffers is the completeness of the record.
		if h.AuditDropped > 0 {
			out = append(out, Alert{
				Kind:     AlertAuditDropping,
				Severity: SeverityWarning,
				Instance: h.Instance,
				Summary:  fmt.Sprintf("Audit events dropped on %q", h.Instance),
				Detail: fmt.Sprintf(
					"%d audit events were discarded because the emitter's buffer was full, so the audit trail and the compliance export are INCOMPLETE for those pulls. Usually means the approval service was slow or unreachable for a sustained period.",
					h.AuditDropped),
			})
		}
		if h.FlowDropped > 0 {
			out = append(out, Alert{
				Kind:     AlertMetricsDropping,
				Severity: SeverityWarning,
				Instance: h.Instance,
				Summary:  fmt.Sprintf("Capacity data dropped on %q", h.Instance),
				Detail: fmt.Sprintf(
					"%d capacity batches could not be delivered, so the dashboard UNDER-reports traffic for those intervals. The numbers shown are a floor, not a total.",
					h.FlowDropped),
			})
		}
	}

	// Transfer failures, counted over a BOUNDED RECENT WINDOW rather than all of history.
	// Evaluating this against the lifetime totals would mean one truncated download three
	// months ago raises an alert forever — an alert that cannot be cleared is one the
	// operator learns to ignore, and then the real one goes unread too. The caller passes
	// the windowed summary; the window is named in the text so nobody reads the count as
	// a lifetime figure.
	if failed := window.Truncated + window.TransportErrors; failed > 0 {
		out = append(out, Alert{
			Kind:     AlertTransferFailing,
			Severity: SeverityWarning,
			Summary:  "Package downloads are failing in transit",
			Detail: fmt.Sprintf(
				"%d transfers failed in the last %s (%d truncated mid-download, %d could not reach the upstream). Developers see these as broken or hanging installs. Note this is a TRANSPORT failure count. Artifact contents are verified only where a digest is available to check — container layers fetched whole, PyPI files whose index this gate relayed, and Maven files whose repository sent a checksum header — and those mismatches are counted separately; for npm a corrupt-but-complete file is still not included here.",
				failed, p.Window, window.Truncated, window.TransportErrors),
		})
	}

	// Critical first, then by kind, then by instance: stable output so a console does not
	// reshuffle between refreshes and a test can assert on order.
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Severity == SeverityCritical) != (out[j].Severity == SeverityCritical) {
			return out[i].Severity == SeverityCritical
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Instance < out[j].Instance
	})
	return out
}
