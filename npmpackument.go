package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Version-level soft blocks for npm (issue #35), and with them the npm half of #103
// (version-pinned advisories) and of #26 (the release cooldown / age floor).
//
// PyPI has had a soft block since !16: a refused release is marked yanked in the
// /simple/ index with the reason, and pip resolves cleanly to the next release. npm had
// the hard version — a refused PACKAGE was a 403 on the packument, and one poisoned
// release failed the whole install. That is the wrong shape for the hijack case: a
// version-pinned advisory names ONE release of a real, widely-used package, and denying
// the name would deny every clean release with it — which is why those advisories were
// loaded and counted but never enforced for npm (the `gap` number in the startup log).
//
// The packument is the control point. npm resolves from the `versions` map and the
// `dist-tags` map of the document we relay, so a version removed from the first and a
// tag repointed in the second steer resolution to the next compliant release before the
// client ever sees the refused one. Two consequences are handled explicitly:
//
//   - dist-tags. Removing a version leaves any tag that named it dangling — Cloudsmith
//     shipped exactly this and then had to ship a per-repo setting to undo their fix,
//     because they repointed `latest` at the highest semver, which is not what the
//     upstream registry meant. We touch ONLY tags that pointed at a removed version,
//     and repoint each at the newest remaining version that is not newer than the one
//     removed (same release/prerelease class preferred): resolution rolls back to the
//     compliant predecessor, and every tag upstream set that we did not disturb stays
//     exactly as upstream set it.
//   - Nothing left. A package whose every version is refused must get a legible 403,
//     not an empty packument that npm reports as "No matching version found".
//
// Two verdicts feed the filter, composed in npmRefuser: a version-pinned known-malware
// advisory (a fact about the release) and the operator's release window (a policy: the
// cooldown FW_MIN_RELEASE_AGE_DAYS and the age floor FW_MAX_RELEASE_AGE_DAYS, judged
// from the packument's own `time` map). The window follows D100: a version whose publish
// time cannot be read is refused while a window is active, because an attacker who can
// make the date go missing would otherwise get exactly the release the window holds
// back. The abbreviated packument npm asks for carries no `time` map at all, so
// openUpstream asks for the full document whenever a window is active.
//
// The byte path is the second control point for advisories: a lockfile-driven `npm ci`
// fetches a tarball by its recorded URL and never reads the packument, so
// proxyArtifactBytes applies the same pinned-advisory verdict to the version in the
// tarball's own filename (npmTarballVersionFromPath, #52). One rule
// (pinnedMalwareVerdict), two places it is asked — the same shape as PyPI's index filter
// plus its /_files/ gate. The release window is index-only, as it is for PyPI: a
// lockfile pin is a deliberate choice the window does not second-guess.
//
// Scoring is unchanged: the firewall still asks upstream for /<pkg>/latest to score the
// package (ecosystem.go), and the packument is parsed only here, in the rewrite of a
// document we were relaying anyway.

// npmVersionFacts is what a refuser is told about one version.
type npmVersionFacts struct {
	Version   string
	Published time.Time // from the packument's `time` map
	HasTime   bool      // false when the document carries no publish time for it
	// InPackument is false for a single version document (/<pkg>/<version>,
	// /<pkg>/latest), which carries no `time` map and is not what npm resolves from;
	// the release window does not apply there, advisories still do.
	InPackument bool
}

// npmRefusalCause says WHICH policy refused a version. It was a bool ("is this an
// advisory?") until #155 added a third cause, and the distinction is not cosmetic: it
// chooses the denial kind, the log token and what the developer is told to do. An advisory
// will not clear by waiting or by asking; a cooldown clears by itself; an operator entry
// clears when a colleague edits the list.
type npmRefusalCause int

const (
	causeWindow npmRefusalCause = iota
	causeMalware
	causeOperator
)

// npmVersionRefuser decides whether one version is refused, and why.
type npmVersionRefuser func(f npmVersionFacts) (reason string, cause npmRefusalCause)

// npmRefusal is one version a verdict removed from a packument, or refused as a
// version document.
type npmRefusal struct {
	Version string
	Reason  string
	Cause   npmRefusalCause
}

// npmFilterResult says what npmFilterMetadata did to a document.
type npmFilterResult struct {
	// Kind is "packument" (has a versions map), "version" (a single version
	// document: /<pkg>/<version> or /<pkg>/latest) or "other".
	Kind      string
	Removed   []npmRefusal
	Remaining int
	// Repointed maps a dist-tag to [from, to]; to == "" means the tag was dropped
	// because nothing remained to point it at.
	Repointed map[string][2]string
	// Refused is set for a version document whose own version the verdict refuses.
	Refused *npmRefusal
	// Undated is set for a packument that carries no `time` map at all: every version
	// in it has no publish date, so an active release window refuses all of them (D100).
	Undated bool
}

// npmFilterMetadata applies `refuse` to every version of an npm metadata document.
// For a packument it removes the refused versions and reconciles dist-tags; for a
// version document it reports whether that version is refused. A document that needs
// no change comes back byte-identical (no re-encoding), so the regex rewrites already
// applied to it are preserved exactly.
func npmFilterMetadata(body []byte, refuse npmVersionRefuser) ([]byte, npmFilterResult, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, npmFilterResult{Kind: "other"}, fmt.Errorf("npm metadata is not a JSON object: %w", err)
	}
	versions, isPackument := doc["versions"].(map[string]any)
	if !isPackument {
		v, _ := doc["version"].(string)
		if v == "" {
			return body, npmFilterResult{Kind: "other"}, nil
		}
		res := npmFilterResult{Kind: "version"}
		if reason, cause := refuse(npmVersionFacts{Version: v}); reason != "" {
			res.Refused = &npmRefusal{Version: v, Reason: reason, Cause: cause}
		}
		return body, res, nil
	}

	times := npmPublishTimes(doc)
	_, dated := doc["time"].(map[string]any)
	res := npmFilterResult{Kind: "packument", Undated: !dated}
	for v := range versions {
		published, hasTime := times[v]
		if reason, cause := refuse(npmVersionFacts{Version: v, Published: published, HasTime: hasTime, InPackument: true}); reason != "" {
			res.Removed = append(res.Removed, npmRefusal{Version: v, Reason: reason, Cause: cause})
		}
	}
	res.Remaining = len(versions) - len(res.Removed)
	if len(res.Removed) == 0 {
		return body, res, nil
	}
	sort.Slice(res.Removed, func(i, j int) bool { return semverCompare(res.Removed[i].Version, res.Removed[j].Version) < 0 })

	removed := make(map[string]bool, len(res.Removed))
	for _, r := range res.Removed {
		removed[r.Version] = true
		delete(versions, r.Version)
	}
	if tm, ok := doc["time"].(map[string]any); ok {
		for v := range removed {
			delete(tm, v)
		}
	}
	remaining := make([]string, 0, len(versions))
	for v := range versions {
		remaining = append(remaining, v)
	}

	if tags, ok := doc["dist-tags"].(map[string]any); ok {
		for tag, target := range tags {
			t, _ := target.(string)
			if !removed[t] {
				continue
			}
			if res.Repointed == nil {
				res.Repointed = map[string][2]string{}
			}
			to := npmRepointTag(t, remaining)
			res.Repointed[tag] = [2]string{t, to}
			if to == "" {
				delete(tags, tag)
			} else {
				tags[tag] = to
			}
		}
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return body, res, fmt.Errorf("re-encode filtered packument: %w", err)
	}
	return out, res, nil
}

// npmPublishTimes reads the packument's `time` map: version -> publish time. The map
// also carries "created" and "modified", which are not versions and are simply never
// looked up. An entry that does not parse is treated as absent, which under an active
// window means refused — the same posture as a missing one.
func npmPublishTimes(doc map[string]any) map[string]time.Time {
	raw, ok := doc["time"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]time.Time, len(raw))
	for v, s := range raw {
		str, _ := s.(string)
		if t, err := time.Parse(time.RFC3339Nano, str); err == nil {
			out[v] = t
		}
	}
	return out
}

// npmRepointTag picks where a dist-tag that named `removed` should point now: the
// newest remaining version not newer than the removed one, preferring the same
// release/prerelease class, so `latest` rolls back to the previous release rather than
// forward onto a beta. If nothing older remains, the newest remaining version; if
// nothing remains at all, "" (drop the tag).
func npmRepointTag(removed string, remaining []string) string {
	if len(remaining) == 0 {
		return ""
	}
	wantPre := semverIsPrerelease(removed)
	best, bestSame := "", ""
	for _, v := range remaining {
		if semverCompare(v, removed) > 0 {
			continue
		}
		if best == "" || semverCompare(v, best) > 0 {
			best = v
		}
		if semverIsPrerelease(v) == wantPre && (bestSame == "" || semverCompare(v, bestSame) > 0) {
			bestSame = v
		}
	}
	if bestSame != "" {
		return bestSame
	}
	if best != "" {
		return best
	}
	newest := remaining[0]
	for _, v := range remaining[1:] {
		if semverCompare(v, newest) > 0 {
			newest = v
		}
	}
	return newest
}

// npmPinnedRefuser is the advisory verdict the packument filter and the resolver test
// share: a version named by a version-pinned known-malware advisory for this package is
// refused with the advisory's ID. Package-wide advisories never reach here — they are
// enforced on the name, before the packument is fetched at all.
func npmPinnedRefuser(list *malwareList, allow *operatorList, pkg string) npmVersionRefuser {
	return func(f npmVersionFacts) (string, npmRefusalCause) {
		if e, found := list.pinnedFor("npm", pkg, f.Version); found {
			// D312: an allow entry naming THIS release outranks the advisory, so the
			// release stays in the packument. Logged by the caller that serves it.
			if allow.hasVersion("npm", pkg, f.Version) {
				return "", causeWindow
			}
			return "known malware: " + e.ID, causeMalware
		}
		return "", causeWindow
	}
}

// npmOperatorRefuser is the operator's own version-scoped deny list (#155) as a packument
// filter: the hijack case in their hands rather than the feed's. One release is removed
// from the packument and its siblings stay installable, which is the whole reason a
// version-scoped entry exists — a name-scoped deny already refuses the package outright,
// before the packument is fetched at all.
//
// The unknown-version branch the byte paths need has no counterpart here: a packument
// names every version it carries, so there is nothing to fail closed about.
func npmOperatorRefuser(deny *operatorList, pkg string) npmVersionRefuser {
	return func(f npmVersionFacts) (string, npmRefusalCause) {
		if deny.hasVersion("npm", pkg, f.Version) {
			return "on this organisation's deny list", causeOperator
		}
		return "", causeWindow
	}
}

// npmWindowRefuser is the release-window verdict (#26): too new for the cooldown, too
// old for the floor, or — while a window is active — no publish time to judge by.
// Inactive windows refuse nothing. Version documents are never judged here (see
// npmVersionFacts.InPackument).
func npmWindowRefuser(w ageWindow) npmVersionRefuser {
	return func(f npmVersionFacts) (string, npmRefusalCause) {
		if !w.active() || !f.InPackument {
			return "", causeWindow
		}
		switch {
		case !f.HasTime:
			return "release age could not be verified (no publish time for this version)", causeWindow
		case !w.tooOldBefore.IsZero() && f.Published.Before(w.tooOldBefore):
			return w.tooOldReason, causeWindow
		case !w.tooNewAfter.IsZero() && f.Published.After(w.tooNewAfter):
			return w.tooNewReason, causeWindow
		}
		return "", causeWindow
	}
}

// npmRefuser composes the verdicts for one package: the advisory first, because it is a
// fact about the release rather than a policy dial and must apply whether or not a
// window is configured; then the window.
func (p *proxyServer) npmRefuser(pkg string, now time.Time) npmVersionRefuser {
	pinned := npmPinnedRefuser(p.firewall.malwareFeed(), p.firewall.allow(), pkg)
	operator := npmOperatorRefuser(p.firewall.deny(), pkg)
	window := npmWindowRefuser(p.releaseWindow(now))
	return func(f npmVersionFacts) (string, npmRefusalCause) {
		if reason, cause := pinned(f); reason != "" {
			return reason, cause
		}
		// The operator's own entry comes after the feed and before the window, the same
		// order Evaluate applies to their name-scoped siblings: if a release is on both,
		// the advisory's reason is the more informative one (it carries a MAL- id).
		if reason, cause := operator(f); reason != "" {
			return reason, cause
		}
		return window(f)
	}
}

// warnIfUpstreamUndated logs, ONCE per process, that the upstream serves packuments with
// no publish dates while a release window is active (D337).
//
// Why it exists: since D335 the cooldown is on by default, and D100 refuses a version
// whose publish time cannot be read. An upstream that never publishes dates -- a private
// registry, an old proxy, a stand-in -- therefore has EVERY package refused, and the only
// evidence was a per-package refusal that reads like a policy verdict. This names the
// cause and the setting on the one surface an operator reads first. It is a warning, not
// a change of verdict: fail-closed on a missing date is deliberate (an attacker who can
// strip the date must not get the release the window holds back).
func (p *proxyServer) warnIfUpstreamUndated(pkg string) {
	if !p.releaseWindow(time.Now()).active() || !p.undatedWarned.CompareAndSwap(false, true) {
		return
	}
	log.Printf("WARNING: upstream %s served the packument for %q with NO publish dates (no `time` map). "+
		"While the release window is active (FW_MIN_RELEASE_AGE_DAYS=%d, FW_MAX_RELEASE_AGE_DAYS=%d) every "+
		"version it serves without a date is REFUSED, by design (D100). If this registry never publishes "+
		"dates, point the gate at one that does, or set FW_MIN_RELEASE_AGE_DAYS=0 to turn the cooldown off. "+
		"Logged once.", p.cfg.UpstreamRegistry, pkg, p.cfg.MinReleaseAgeDays, p.cfg.MaxReleaseAgeDays)
}

// npmRefusalToken is the log token for a whole-packument refusal, chosen by WHY it was
// refused. It used to be a literal "[known-malware]" for every cause, so a package held
// by the cooldown was logged as malware -- harmless while the window defaulted to off,
// and the commonest refusal an operator would read once it defaulted to 14 days (D335).
// The per-version lines below already chose by cause; this is the same mapping.
func npmRefusalToken(d Decision) string {
	switch d.Deny {
	case denyReleaseWindow:
		return "[release-window]"
	case denyOperator:
		return "[operator-denied]"
	}
	return "[known-malware]"
}

// npmFilterPackumentForRelay is relayRewritten's npm hook. It returns the body to
// serve, or a Decision to refuse the request with (a version document of a refused
// version, or a packument with nothing compliant left). The log lines it writes are
// the operator's record of every version steered around.
func (p *proxyServer) npmFilterPackumentForRelay(r *http.Request, body []byte, pkg string) ([]byte, *Decision) {
	out, res, err := npmFilterMetadata(body, p.npmRefuser(pkg, time.Now()))
	if err == nil && res.Undated {
		p.warnIfUpstreamUndated(pkg)
	}
	if err != nil {
		// Not a document we understand — a registry-specific shape, an error page with
		// a 200. Served as relayed: there is nothing to filter, and nothing was hidden.
		log.Printf("%s %s -> npm metadata not filtered (%v); served as relayed", r.Method, pkg, err)
		return body, nil
	}
	if res.Refused != nil {
		if res.Refused.Cause == causeOperator {
			return body, &Decision{
				Allowed: false,
				Deny:    denyOperator,
				Rule:    "deny-list:" + joinOperatorEntry("npm", pkg, res.Refused.Version),
				Source:  sourceDenyList,
				Reason: fmt.Sprintf("version %q of %q is on this organisation's deny list; other versions are "+
					"not affected. This is a local policy decision, not a published malware advisory — ask "+
					"whoever maintains the firewall's deny list", res.Refused.Version, pkg),
			}
		}
		id := strings.TrimPrefix(res.Refused.Reason, "known malware: ")
		return body, &Decision{
			Allowed: false,
			Deny:    denyKnownMalware,
			Rule:    id,
			Source:  sourceMalwareFeed,
			Reason:  fmt.Sprintf("version %q of %q is listed as known malware (%s)", res.Refused.Version, pkg, id),
		}
	}
	if len(res.Removed) > 0 && res.Remaining == 0 {
		// Nothing compliant remains. The denial kind follows the CAUSE, because the
		// developer's next step differs: an advisory will not clear by waiting or by
		// asking; a cooldown clears by itself with time.
		malware, operator, firstID := 0, 0, ""
		items := make([]string, 0, len(res.Removed))
		for _, rm := range res.Removed {
			switch rm.Cause {
			case causeMalware:
				malware++
				if firstID == "" {
					firstID = strings.TrimPrefix(rm.Reason, "known malware: ")
				}
			case causeOperator:
				operator++
			}
			items = append(items, rm.Version+" ("+strings.TrimPrefix(rm.Reason, "known malware: ")+")")
		}
		// Every remaining version was refused by the operator's own list. Their reason
		// names the ORGANISATION as the decider and points at a colleague, not at us
		// (D137) — the same wording the name-scoped deny uses in Evaluate.
		if operator == len(res.Removed) {
			return body, &Decision{
				Allowed: false,
				Deny:    denyOperator,
				Rule:    "deny-list:" + pkg,
				Source:  sourceDenyList,
				Reason: fmt.Sprintf("every version of %q is on this organisation's deny list: %s. This is a "+
					"local policy decision, not a published malware advisory — ask whoever maintains the "+
					"firewall's deny list", pkg, strings.Join(items, ", ")),
			}
		}
		// The rule named is the first advisory that fired, or the window; the source
		// names every policy involved, so a mixed refusal is attributable to both.
		switch {
		case malware == len(res.Removed):
			return body, &Decision{
				Allowed: false,
				Deny:    denyKnownMalware,
				Rule:    firstID,
				Source:  sourceMalwareFeed,
				Reason:  fmt.Sprintf("every version of %q is listed as known malware: %s", pkg, strings.Join(items, ", ")),
			}
		case malware > 0:
			return body, &Decision{
				Allowed: false,
				Deny:    denyKnownMalware,
				Rule:    firstID,
				Source:  sourceMalwareFeed + "; " + sourceReleaseWindow,
				Reason:  fmt.Sprintf("every version of %q is refused, %d of %d as known malware: %s", pkg, malware, len(res.Removed), strings.Join(items, ", ")),
			}
		}
		return body, &Decision{
			Allowed: false,
			Deny:    denyReleaseWindow,
			Rule:    "release-window",
			Source:  sourceReleaseWindow,
			Reason:  fmt.Sprintf("every version of %q is outside the configured release window: %s", pkg, strings.Join(items, ", ")),
		}
	}
	for _, rm := range res.Removed {
		token := "[release-window]"
		switch rm.Cause {
		case causeMalware:
			token = "[known-malware]"
		case causeOperator:
			token = "[operator-denied]"
		}
		log.Printf("%s %s %s -> version %s removed from the packument (%s); %d versions remain",
			r.Method, token, pkg, rm.Version, rm.Reason, res.Remaining)
	}
	for tag, ft := range res.Repointed {
		if ft[1] == "" {
			log.Printf("%s %s -> dist-tag %q dropped: it named refused version %s and nothing older remains", r.Method, pkg, tag, ft[0])
		} else {
			log.Printf("%s %s -> dist-tag %q repointed from refused version %s to %s", r.Method, pkg, tag, ft[0], ft[1])
		}
	}
	return out, nil
}
