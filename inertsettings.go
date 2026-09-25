package main

import "fmt"

// inertSettingWarnings returns one operator warning for every control that is CONFIGURED
// on this gate and that this gate CANNOT ENFORCE, or nil when there is nothing to say.
//
// ── WHY THIS EXISTS ──────────────────────────────────────────────────────
//
// A control over an input the gate does not have is not "off". It is ON in the operator's
// head and off in the request path, and nothing about a request ever reveals the
// difference: a rule that can never match looks exactly like a rule that has not matched
// yet. #150 found the first live instance -- a release-age window set on an OCI gate, where
// there is no trustworthy release date to judge by (see whyOCIHasNoReleaseWindow) -- and
// fixed the page an operator reads AFTER deployment (/policy). This is the other half: say
// so at STARTUP, in the same banner that prints the setting, when the person who typed it
// is still looking.
//
// ── WHY A WARNING AND NOT A REFUSAL TO START ─────────────────────────────
//
// #19 made a MALFORMED value fatal, because a malformed value has no meaning at all. An
// inert value is different: it is well-formed, and it is frequently the product of one
// environment file shared by several gates, where it is meaningful for npm and inert for
// the image gate beside it. Refusing to start would turn a truthful shared file into an
// outage. The refusal belongs to a policy DOCUMENT, where a rule is written for one gate
// and naming an unavailable input can only be a mistake; when that format exists it should
// fail to load, and this function is where that check will find its list.
//
// It reads releaseWindowEnforced rather than re-deriving it, so the startup banner and
// /policy cannot disagree about whether the window applies.
func (f *Firewall) inertSettingWarnings() []string {
	var out []string
	if !f.releaseWindowEnforced() {
		for _, k := range []struct {
			name string
			days int
		}{
			{"FW_MIN_RELEASE_AGE_DAYS", f.cfg.MinReleaseAgeDays},
			{"FW_MAX_RELEASE_AGE_DAYS", f.cfg.MaxReleaseAgeDays},
		} {
			if k.days > 0 {
				out = append(out, fmt.Sprintf("%s=%d is set but is NOT ENFORCED on this %s gate: there is no "+
					"trustworthy release date to judge by (#127), so no pull will ever be held or refused by it. "+
					"Remove it from this gate's environment, or accept that it has no effect here.",
					k.name, k.days, f.cfg.Ecosystem))
			}
		}
	}
	return out
}
