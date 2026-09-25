package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingLauncher measures how many scans are genuinely running at once.
//
// The decrement happens BEFORE the report is POSTed, deliberately: the scheduler
// releases a launch slot only when its /scan handler returns, which happens after
// the report is delivered. Decrementing after the POST would let a queued scan's
// increment race ahead of this scan's decrement and report a phantom overshoot.
type countingLauncher struct {
	hold time.Duration // how long a "scan" occupies its slot

	mu      sync.Mutex
	current int
	max     int

	launches atomic.Int64
}

func (l *countingLauncher) Launch(ctx context.Context, repo, sinkURL string) error {
	l.launches.Add(1)
	l.mu.Lock()
	l.current++
	if l.current > l.max {
		l.max = l.current
	}
	l.mu.Unlock()

	go func() {
		time.Sleep(l.hold)

		l.mu.Lock()
		l.current--
		l.mu.Unlock()

		body, _ := json.Marshal(scanReport{Repo: repo, Result: &scanResult{Repo: repo, Score: 7}})
		resp, err := http.Post(sinkURL, "application/json", bytes.NewReader(body))
		if err == nil {
			resp.Body.Close()
		}
	}()
	return nil
}

func (l *countingLauncher) observedMax() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.max
}

// The cap is the whole point of item 3: a burst of concurrent /scan calls must never
// have more than N containers alive at once. Run under -race.
func TestScanLaunchesAreCapped(t *testing.T) {
	const maxScans, callers = 3, 15
	l := &countingLauncher{hold: 40 * time.Millisecond}
	_, ts := newTestSchedulerCapped(t, l, 10*time.Second, maxScans)

	var wg sync.WaitGroup
	statuses := make([]int, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Not postScan: it calls t.Fatalf, which is illegal off the test goroutine.
			resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader([]byte(`{"repo":"github.com/example/pkg"}`)))
			if err != nil {
				statuses[i] = -1
				return
			}
			defer resp.Body.Close()
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	if got := l.observedMax(); got > maxScans {
		t.Errorf("%d scans ran concurrently, cap is %d", got, maxScans)
	}
	// Capping must not LOSE work: every caller still got its scan, just later.
	if got := l.launches.Load(); got != callers {
		t.Errorf("%d scans launched, want all %d", got, callers)
	}
	for i, st := range statuses {
		if st != http.StatusOK {
			t.Errorf("caller %d got status %d, want 200 — queued callers must still be served", i, st)
		}
	}
}

// Uncapped (0) keeps the old behavior, so an operator bounding launches elsewhere
// isn't forced into ours.
func TestUncappedSchedulerDoesNotQueue(t *testing.T) {
	const callers = 12
	l := &countingLauncher{hold: 40 * time.Millisecond}
	_, ts := newTestSchedulerCapped(t, l, 10*time.Second, 0)

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader([]byte(`{"repo":"r"}`)))
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	// Not asserting max == callers (the goroutines needn't overlap perfectly), only
	// that nothing was serialized down to the capped level.
	if got := l.observedMax(); got <= 1 {
		t.Errorf("observed max concurrency %d — uncapped mode should not serialize", got)
	}
}

// A caller that cannot get a slot within its whole deadline is shed with a 503 —
// NOT a 502/504, because the firewall reads those as "this repo is unscorable" and
// would block the package under the fail-closed default. Saturation is our problem,
// not a verdict on the package.
func TestScanAtCapacityShedsWith503(t *testing.T) {
	l := &countingLauncher{hold: time.Hour} // never reports; the slot stays taken
	s, ts := newTestSchedulerCapped(t, l, 150*time.Millisecond, 1)

	// Occupy the only slot deterministically, rather than racing a real scan for it.
	s.launchSlots <- struct{}{}

	start := time.Now()
	resp := postScan(t, ts, "github.com/example/pkg")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 at capacity", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("a shed request should carry Retry-After so the client backs off")
	}
	if l.launches.Load() != 0 {
		t.Errorf("%d scans launched while at capacity, want 0", l.launches.Load())
	}
	// It waited for the deadline before shedding, rather than failing fast.
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("shed after %s — should queue for the full deadline first", elapsed)
	}
}

// acquireSlot's contract, unit-level: permits are exclusive, released permits are
// reusable, and a caller whose context expires while queueing is refused.
func TestAcquireSlot(t *testing.T) {
	s := newScheduler(&fakeLauncher{silent: true}, "http://x", time.Second, 1)

	release, ok := s.acquireSlot(context.Background(), "r")
	if !ok {
		t.Fatal("first acquire should succeed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, ok := s.acquireSlot(ctx, "r"); ok {
		t.Error("second acquire should fail while the only slot is held")
	}

	release()
	if _, ok := s.acquireSlot(context.Background(), "r"); !ok {
		t.Error("a released slot should be reusable")
	}
}

// Uncapped must never block, even on an already-dead context.
func TestAcquireSlotUncapped(t *testing.T) {
	s := newScheduler(&fakeLauncher{silent: true}, "http://x", time.Second, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := s.acquireSlot(ctx, "r"); !ok {
		t.Error("uncapped acquire should always succeed")
	}
}
