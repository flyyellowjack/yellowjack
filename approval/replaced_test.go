package main

import (
	"testing"
	"time"
)

// Each case is one shape a fleet takes. The negatives are the ones that matter: a rule that
// marks every silent replica "replaced" would make a dead firewall vanish from the view that
// exists to notice it, so every way a replica genuinely dies must stay silent.
func TestMarkReplaced(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	boot := now.Add(-48 * time.Hour)
	row := func(name, eco string, started, reported time.Time) InstanceHealth {
		return InstanceHealth{Instance: name, Ecosystem: eco, StartedAt: started, ReportedAt: reported}
	}
	fresh := now.Add(-30 * time.Second)
	wentQuiet := now.Add(-2 * time.Hour)

	cases := []struct {
		name string
		rows []InstanceHealth
		want map[string]string // instance -> ReplacedBy ("" = not replaced)
	}{
		{"a rolling update: the successor started just before the old one's last heartbeat",
			[]InstanceHealth{row("old", "npm", boot, wentQuiet), row("new", "npm", wentQuiet.Add(-90*time.Second), fresh)},
			map[string]string{"old": "new", "new": ""}},
		{"a container recreated: the successor started just after",
			[]InstanceHealth{row("old", "npm", boot, wentQuiet), row("new", "npm", wentQuiet.Add(20*time.Second), fresh)},
			map[string]string{"old": "new"}},
		{"NEGATIVE: a replica died and nothing replaced it",
			[]InstanceHealth{row("dead", "npm", boot, wentQuiet), row("peer", "npm", boot, fresh)},
			map[string]string{"dead": "", "peer": ""}},
		{"NEGATIVE: a scale-up long before a crash does not explain the crash away",
			[]InstanceHealth{row("crashed", "npm", boot, wentQuiet), row("added", "npm", boot.Add(time.Hour), fresh)},
			map[string]string{"crashed": ""}},
		{"NEGATIVE: a successor of ANOTHER ecosystem does not count",
			[]InstanceHealth{row("old-npm", "npm", boot, wentQuiet), row("new-oci", "oci", wentQuiet, fresh)},
			map[string]string{"old-npm": ""}},
		{"NEGATIVE: an unknown start time is never evidence (gates that predate started_at)",
			[]InstanceHealth{row("old", "npm", time.Time{}, wentQuiet), row("new", "npm", wentQuiet, fresh)},
			map[string]string{"old": ""}},
		{"NEGATIVE: a successor must itself be alive",
			[]InstanceHealth{row("old", "npm", boot, wentQuiet.Add(-time.Hour)), row("also-gone", "npm", wentQuiet.Add(-time.Hour), wentQuiet)},
			map[string]string{"old": ""}},
		{"NEGATIVE: a live replica is never marked, even with a younger peer",
			[]InstanceHealth{row("live", "npm", boot, fresh), row("younger", "npm", now.Add(-time.Minute), fresh)},
			map[string]string{"live": "", "younger": ""}},
		{"one successor accounts for ONE predecessor: the one it replaced, not an older death",
			[]InstanceHealth{
				row("died-yesterday", "npm", boot, now.Add(-20*time.Hour)),
				row("replaced", "npm", boot, wentQuiet),
				row("new", "npm", wentQuiet.Add(-time.Minute), fresh)},
			map[string]string{"died-yesterday": "", "replaced": "new"}},
		{"a whole fleet redeployed: each old replica is matched to its own successor",
			[]InstanceHealth{
				row("a", "npm", boot, wentQuiet), row("b", "npm", boot, wentQuiet.Add(time.Minute)),
				row("c", "npm", wentQuiet.Add(-time.Minute), fresh), row("d", "npm", wentQuiet.Add(30*time.Second), fresh)},
			nil}, // asserted below: which pairing wins a tie does not matter, that both are covered does
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := append([]InstanceHealth(nil), tc.rows...)
			markReplaced(rows, now, 15*time.Minute)
			got := map[string]string{}
			for _, r := range rows {
				got[r.Instance] = r.ReplacedBy
			}
			if tc.want == nil {
				if got["a"] == "" || got["b"] == "" || got["a"] == got["b"] {
					t.Errorf("a whole fleet redeployed: a=%q b=%q, want each matched to a DIFFERENT successor", got["a"], got["b"])
				}
				return
			}
			for inst, want := range tc.want {
				if got[inst] != want {
					t.Errorf("%s: ReplacedBy = %q, want %q", inst, got[inst], want)
				}
			}
		})
	}
}

// The consequence that made this worth fixing: a redeploy raised a CRITICAL "has stopped
// reporting" alert per replaced replica, for ever. A replaced replica raises none; a dead
// one still raises its alert.
func TestAReplacedReplicaRaisesNoSilentAlert(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	quiet := now.Add(-2 * time.Hour)
	health := []InstanceHealth{
		{Instance: "old", Ecosystem: "npm", StartedAt: now.Add(-48 * time.Hour), ReportedAt: quiet},
		{Instance: "new", Ecosystem: "npm", StartedAt: quiet.Add(-time.Minute), ReportedAt: now},
		{Instance: "dead", Ecosystem: "pypi", StartedAt: now.Add(-48 * time.Hour), ReportedAt: quiet},
	}
	var silent []string
	for _, a := range evaluateAlerts(now, health, FlowSummary{}, defaultAlertParams()) {
		if a.Kind == AlertInstanceSilent {
			silent = append(silent, a.Instance)
		}
	}
	if len(silent) != 1 || silent[0] != "dead" {
		t.Fatalf("silent alerts for %v, want exactly [dead]: the replaced replica must not alert, the dead one must", silent)
	}
	if health[0].ReplacedBy != "" {
		t.Error("evaluateAlerts wrote into its caller's rows; it must stay pure")
	}
}
