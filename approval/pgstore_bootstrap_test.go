package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// N REPLICAS BOOTSTRAPPING THE SCHEMA AT THE SAME MOMENT (#23 last box, D210).
//
// "Config database is bootstrapped" has an easy reading -- migrate() runs at start --
// and the reading D133 actually needs: N replicas coming up TOGETHER on a fresh install
// must not race the schema creation. newPGStore runs Ping then migrate() with no lock,
// and migrate() is a chain of CREATE TABLE / CREATE INDEX ... IF NOT EXISTS. Postgres
// does not make IF NOT EXISTS race-safe: two sessions can both pass the existence check
// and the loser dies with a duplicate-key error on pg_type_typname_nsp_index or
// pg_class_relname_nsp_index. That process exits ("database init failed"), which on
// Kubernetes is a crash loop on first boot -- exactly when every replica starts at once.
//
// WHY THIS IS A GO TEST AND NOT A DOCKER DRILL. e2e/ha_drill.sh tried to race real
// containers and measured that Docker Desktop starts them 300-400ms apart: eight
// "concurrent" replicas spanned 2.3-3.4s, wider than the whole migration takes, so
// nothing ever raced and a clean result proved nothing. Goroutines start microseconds
// apart. This exercises the SAME newPGStore path the container runs, against a real
// Postgres, with concurrency the instrument can actually produce -- and the drill's leg
// 8 now runs this test rather than pretending with containers.
//
// Needs APPROVAL_TEST_DSN, like the other Postgres-backed tests here; skips without it.
// It DROPS every table the schema owns before each attempt, because the race exists
// only on an empty schema -- so point it at a throwaway database.

// schemaTables is every table migrate() creates. Dropped between attempts; if a
// migration adds a table and this list is not updated, the new table survives the wipe
// and that part of the bootstrap is never raced -- so the count is asserted below.
var schemaTables = []string{
	"decisions", "scores", "events", "flow_buckets", "flow_ip_buckets",
	"instance_health", "alert_notifications", "false_positives",
}

func bootstrapEnv(t *testing.T) (dsn string, replicas, attempts int) {
	t.Helper()
	dsn = os.Getenv("APPROVAL_TEST_DSN")
	if dsn == "" {
		t.Skip("APPROVAL_TEST_DSN not set; a concurrent bootstrap is meaningless without a real Postgres")
	}
	replicas, attempts = 16, 5
	if v, err := strconv.Atoi(os.Getenv("YJ_BOOT_REPLICAS")); err == nil && v > 1 {
		replicas = v
	}
	if v, err := strconv.Atoi(os.Getenv("YJ_BOOT_ATTEMPTS")); err == nil && v > 0 {
		attempts = v
	}
	return dsn, replicas, attempts
}

func wipeSchema(t *testing.T, dsn string) {
	t.Helper()
	pg, err := newPGStore(dsn)
	if err != nil {
		t.Fatalf("APPROVAL_TEST_DSN set but unusable: %v", err)
	}
	defer pg.db.Close()
	for _, tbl := range schemaTables {
		if _, err := pg.db.Exec("DROP TABLE IF EXISTS " + tbl + " CASCADE"); err != nil {
			t.Fatalf("drop %s: %v", tbl, err)
		}
	}
	// Anti-vacuity for the wipe itself: nothing of ours may remain, or the attempt
	// below races a schema that already exists and cannot fail.
	var left int
	if err := pg.db.QueryRow(`SELECT count(*) FROM pg_tables WHERE schemaname = 'public'`).Scan(&left); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if left != 0 {
		t.Fatalf("%d table(s) survived the wipe -- schemaTables is missing something, and the "+
			"surviving part of the bootstrap would never be raced", left)
	}
}

// TestConcurrentBootstrapDoesNotRace is the assertion: every one of N simultaneous
// newPGStore calls against an EMPTY database must succeed, every attempt.
func TestConcurrentBootstrapDoesNotRace(t *testing.T) {
	dsn, replicas, attempts := bootstrapEnv(t)
	total, failed := 0, 0
	var firstErr string
	for a := 1; a <= attempts; a++ {
		wipeSchema(t, dsn)

		var wg sync.WaitGroup
		errs := make([]error, replicas)
		start := make(chan struct{})
		for i := 0; i < replicas; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start // every goroutine is parked here, then released together
				pg, err := newPGStore(dsn)
				if err == nil {
					pg.db.Close()
				}
				errs[i] = err
			}(i)
		}
		close(start)
		wg.Wait()

		for _, err := range errs {
			total++
			if err != nil {
				failed++
				if firstErr == "" {
					firstErr = err.Error()
				}
			}
		}
	}
	if failed != 0 {
		t.Fatalf("%d of %d concurrent bootstraps FAILED across %d attempts.\n"+
			"  first error: %s\n"+
			"  On Kubernetes this is a crash loop on first boot: every replica of the approval\n"+
			"  service starts at once against an empty database, and the losers of this race\n"+
			"  exit with \"database init failed\". The migration must be serialised across\n"+
			"  processes (an advisory lock), not merely made idempotent within one.",
			failed, total, attempts, firstErr)
	}
	t.Logf("%d concurrent bootstraps across %d attempts, 0 failures", total, attempts)
}

// TestConcurrentBootstrapInstrumentCanSeeAFailure is the negative control: the counting
// above must be able to register an error, or a broken harness reads as HA-safe.
func TestConcurrentBootstrapInstrumentCanSeeAFailure(t *testing.T) {
	dsn, _, _ := bootstrapEnv(t)
	// A DSN pointing at a database that does not exist must fail Ping, and that failure
	// must surface through the same newPGStore path the test above counts.
	bad := strings.Replace(dsn, "/yjtest", "/yj_definitely_not_here", 1)
	if bad == dsn {
		// The DSN did not name yjtest (a local override); corrupt the database name generically.
		i := strings.LastIndex(dsn, "/")
		bad = dsn[:i+1] + "yj_definitely_not_here" + dsn[strings.IndexAny(dsn[i:], "?")+i:]
	}
	// Zero window: this must fail NOW, not after the 60s startup retry newPGStore gives a
	// dependency that is not there yet. A nonexistent database is not "not there yet".
	if _, err := newPGStoreWithin(bad, 0); err == nil {
		t.Fatal("newPGStore succeeded against a database that does not exist, so a failed " +
			"bootstrap above could go uncounted")
	}
}

// TestStartupRetriesAnUnreachableDatabaseThenGivesUp pins both halves of the retry:
// it keeps trying inside the window, and it STOPS at the window's edge with the last
// error rather than turning a wrong DSN into a process that never comes up.
func TestStartupRetriesAnUnreachableDatabaseThenGivesUp(t *testing.T) {
	// A port nothing listens on: every Ping is refused immediately, so the elapsed time
	// is the retry loop's own, not the network's.
	const dead = "postgres://postgres:x@127.0.0.1:1/nothing?sslmode=disable&connect_timeout=1"
	start := time.Now()
	_, err := newPGStoreWithin(dead, 1200*time.Millisecond)
	took := time.Since(start)
	if err == nil {
		t.Fatal("a database on a closed port was opened")
	}
	if !strings.Contains(err.Error(), "gave up after") {
		t.Fatalf("the error does not say it retried and gave up: %v", err)
	}
	// The window is 1.2s and the first backoff is 0.5s, so at least two attempts fit
	// (0, 0.5, 1.5 -> the third is past the deadline). Fewer than 2 means no retry
	// happened; much more than the window plus one backoff means it did not stop.
	if took < 1*time.Second {
		t.Fatalf("gave up after %s -- it did not retry inside the 1.2s window", took)
	}
	if took > 4*time.Second {
		t.Fatalf("took %s to give up on a 1.2s window -- the deadline is not being honoured", took)
	}
	t.Logf("retried and gave up in %s: %v", took.Round(10*time.Millisecond), err)
}
