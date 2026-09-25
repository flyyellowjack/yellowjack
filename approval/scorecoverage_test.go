package main

import (
	"net/http"
	"reflect"
	"testing"
)

// Coverage on the L2 score record (#133). Before this, the cache stored only the
// number, so a partial score that had passed the gate's required-check floor (D271)
// was indistinguishable from a full one on the control plane and on every page that
// read it. These run against memStore always and pgStore when APPROVAL_TEST_DSN is set;
// the Postgres leg is the one that proves the three new columns round-trip.

func TestScoreRecordPartial(t *testing.T) {
	cases := []struct {
		scored, total int
		want          bool
	}{
		{0, 0, false},   // older row / older scanner: unknown, not partial
		{18, 18, false}, // full
		{15, 18, true},
		{0, 18, true}, // nothing scored: still partial (the floor would have refused it)
	}
	for _, c := range cases {
		got := ScoreRecord{ScoredChecks: c.scored, TotalChecks: c.total}.Partial()
		if got != c.want {
			t.Errorf("Partial(%d of %d) = %v, want %v", c.scored, c.total, got, c.want)
		}
	}
}

func TestScoreCoverageRoundTripsThroughEveryBackend(t *testing.T) {
	for name, store := range eventStores(t) {
		t.Run(name, func(t *testing.T) {
			score := 6.2
			in := ScoreRecord{Repo: "gitlab.example/org/partial-" + name, Score: &score,
				ScoredChecks: 15, TotalChecks: 18, ComputedWithout: []string{"CI-Tests", "Contributors", "License"}}
			if _, err := store.PutScore(in); err != nil {
				t.Fatalf("PutScore: %v", err)
			}
			rec, ok, err := store.GetScore(in.Repo)
			if err != nil || !ok {
				t.Fatalf("GetScore = (ok=%v, err=%v)", ok, err)
			}
			if rec.Score == nil || *rec.Score != 6.2 {
				t.Fatalf("the number itself did not round-trip: %+v", rec)
			}
			if !rec.Partial() || rec.ScoredChecks != 15 || rec.TotalChecks != 18 {
				t.Errorf("coverage did not round-trip: got %d of %d (partial=%v), want 15 of 18", rec.ScoredChecks, rec.TotalChecks, rec.Partial())
			}
			if !reflect.DeepEqual(rec.ComputedWithout, in.ComputedWithout) {
				t.Errorf("computedWithout = %v, want %v", rec.ComputedWithout, in.ComputedWithout)
			}

			// A later FULL scan of the same repo must clear the shortfall, not leave
			// the old names beside the new number.
			if _, err := store.PutScore(ScoreRecord{Repo: in.Repo, Score: &score, ScoredChecks: 18, TotalChecks: 18}); err != nil {
				t.Fatalf("PutScore full: %v", err)
			}
			rec, _, _ = store.GetScore(in.Repo)
			if rec.Partial() || len(rec.ComputedWithout) != 0 {
				t.Errorf("a full re-scan left the old coverage behind: %+v", rec)
			}

			// A record written with no coverage at all reads back as unknown.
			old := "gitlab.example/org/old-" + name
			if _, err := store.PutScore(ScoreRecord{Repo: old, Score: &score}); err != nil {
				t.Fatalf("PutScore old: %v", err)
			}
			rec, _, _ = store.GetScore(old)
			if rec.Partial() || rec.ComputedWithout != nil {
				t.Errorf("a record with no coverage reads as partial or names checks: %+v", rec)
			}
		})
	}
}

// TestPackageStatusCarriesTheScoresCoverage: the read-only aggregate hands the record
// through unchanged, and a partial score that reached the cache is still "present" --
// it passed the floor, so it IS a score; the coverage is what tells the reader which
// kind.
func TestPackageStatusCarriesTheScoresCoverage(t *testing.T) {
	srv := newStatusServer(t)
	const repo = "gitlab.example/org/repo"
	if _, err := srv.store.Put(Decision{Package: "partial-pkg", Verdict: VerdictApproved, RepoURL: repo, DecidedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	score := 6.2
	if _, err := srv.store.PutScore(ScoreRecord{Repo: repo, Score: &score, ScoredChecks: 15, TotalChecks: 18,
		ComputedWithout: []string{"CI-Tests", "Contributors", "License"}}); err != nil {
		t.Fatal(err)
	}
	code, st := getStatus(t, srv, "package=partial-pkg")
	if code != http.StatusOK || st.Score == nil {
		t.Fatalf("status = %d, score = %+v", code, st.Score)
	}
	if st.ScoreAvailability != availPresent {
		t.Errorf("ScoreAvailability = %q, want %q: a partial score that passed the floor is a score", st.ScoreAvailability, availPresent)
	}
	if !st.Score.Partial() || st.Score.ScoredChecks != 15 || st.Score.TotalChecks != 18 || len(st.Score.ComputedWithout) != 3 {
		t.Errorf("the aggregate dropped the coverage: %+v", st.Score)
	}
}
