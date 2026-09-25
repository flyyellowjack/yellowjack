package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Verdict determinism (issue #45).
//
// Every other test proves a decision is CORRECT for some input. None proved the same
// input yields the same decision twice, or under load. For a blocking gate that is a
// correctness property, not polish: the same pull allowed at 3am and blocked at peak
// is indistinguishable from an outage, and it destroys the one thing a firewall sells
// — a decision you can rely on.
//
// Traced to a real finding. Datadog GuardDog #613: the same package, same version,
// scanned repeatedly, produced different results run to run — on simple-swizzle 0.2.3,
// which carried real malware. Their own diagnosis was "a combination of current system
// load and payload complexity". It stayed open ~10 months. GuardDog is a batch CLI; we
// are a blocking proxy, so the same defect costs us more.
//
// Go makes this live via map iteration order and goroutine scheduling, and we already
// have a load-dependent behaviour on file (#1).

// determinismUpstream serves npm packuments for a handful of scenario packages, so
// Evaluate exercises the real resolve → score → policy path with no network.
func determinismUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	repos := map[string]string{
		"/goodpkg":   `{"repository":{"url":"git+https://github.com/good/repo.git"}}`,
		"/alphapkg":  `{"repository":{"url":"git+https://github.com/alpha/repo.git"}}`,
		"/betapkg":   `{"repository":{"url":"git+https://github.com/beta/repo.git"}}`,
		"/norepopkg": `{"name":"norepopkg"}`, // no repository field -> unscorable
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for path, body := range repos {
			if r.URL.Path == path || r.URL.Path == path+"/latest" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// verdict is the full observable outcome of one evaluation. Every field is compared,
// INCLUDING the reason string: a gate that blocks consistently but explains itself
// differently each time is still non-deterministic to the human debugging it, and the
// reason is what the developer and the audit record both see.
type verdict struct {
	Allowed     bool
	Score       float64
	HasScore    bool
	Unavailable bool
	Pending     bool
	Deny        denyKind
	Reason      string
}

func verdictOf(d Decision) verdict {
	return verdict{d.Allowed, d.Score, d.HasScore, d.Unavailable, d.Pending, d.Deny, d.Reason}
}

// TestVerdictIsRepeatable: the same package, same config, evaluated many times in a
// row, yields a byte-identical outcome. Repetition matters because the FIRST call and
// the rest take different internal paths — the first resolves and scores, later ones
// may be served by the L1 repo/score caches. Same answer either way, or the cache is
// changing verdicts.
func TestVerdictIsRepeatable(t *testing.T) {
	upstream := determinismUpstream(t)

	configs := []struct {
		name   string
		mutate func(*Config)
	}{
		{"default", nil},
		{"fail-closed unscorable", func(c *Config) { c.UnscorablePolicy = "block" }},
		{"fail-open unscorable", func(c *Config) { c.UnscorablePolicy = "allow" }},
		{"threshold above the stub score", func(c *Config) { c.ScoreThreshold = 9.9 }},
		{"threshold below the stub score", func(c *Config) { c.ScoreThreshold = 1.0 }},
		{"caching disabled", func(c *Config) { c.ScoreCacheTTL = 0 }},
	}
	packages := []string{"goodpkg", "norepopkg", "nosuchpkg"}

	for _, cfg := range configs {
		for _, pkg := range packages {
			t.Run(cfg.name+"/"+pkg, func(t *testing.T) {
				p := newTestProxy(t, upstream, cfg.mutate)
				first := verdictOf(p.firewall.Evaluate(pkg))
				for i := 2; i <= 200; i++ {
					got := verdictOf(p.firewall.Evaluate(pkg))
					if got != first {
						t.Fatalf("evaluation %d of %q differs from the first — the same input produced two verdicts.\n"+
							"first: %+v\nnow:   %+v", i, pkg, first, got)
					}
				}
			})
		}
	}
}

// TestVerdictIsStableUnderConcurrentLoad is the half the GuardDog defect was actually
// about: "current system load" changing the answer.
//
// Deliberately runs MIXED packages through one Firewall so the caches, the
// single-flight groups and the goroutine scheduler are all contended — evaluating one
// package in isolation would not exercise the paths where load leaks in.
func TestVerdictIsStableUnderConcurrentLoad(t *testing.T) {
	upstream := determinismUpstream(t)
	p := newTestProxy(t, upstream, nil)

	packages := []string{"goodpkg", "alphapkg", "betapkg", "norepopkg", "nosuchpkg"}

	// The uncontended answer, taken first on a quiet firewall.
	want := map[string]verdict{}
	for _, pkg := range packages {
		want[pkg] = verdictOf(p.firewall.Evaluate(pkg))
	}

	const workers = 64
	const perWorker = 25

	var mu sync.Mutex
	var mismatches []string

	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start // release them together, to maximise contention
			for i := 0; i < perWorker; i++ {
				pkg := packages[(w+i)%len(packages)]
				got := verdictOf(p.firewall.Evaluate(pkg))
				if got != want[pkg] {
					mu.Lock()
					mismatches = append(mismatches, fmt.Sprintf("%s: quiet=%+v under-load=%+v", pkg, want[pkg], got))
					mu.Unlock()
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()

	if len(mismatches) > 0 {
		t.Fatalf("%d of %d concurrent evaluations disagreed with the uncontended verdict — "+
			"load changed the decision, which is the GuardDog #613 defect:\n  %s",
			len(mismatches), workers*perWorker, mismatches[0])
	}
}

// TestPolicyOrderIsStableAcrossConstructions pins the third acceptance item: no
// iteration over a rule set may depend on map order.
//
// Asserted behaviourally rather than by grepping for `range` over a map, because Go
// gives no syntactic tell — `for _, r := range x` reads identically for a slice and a
// map. Building the same policy repeatedly and comparing the ORDERED rule names and
// the digest catches the thing that actually matters: if a chain were ever backed by a
// map, these would vary run to run. (Go deliberately randomises map iteration order,
// so this fails fast rather than intermittently.)
func TestPolicyOrderIsStableAcrossConstructions(t *testing.T) {
	cfg := Config{
		Ecosystem:        "npm",
		UpstreamRegistry: "https://registry.npmjs.org",
		UnscorablePolicy: "block",
		ScoreThreshold:   5.0,
		ScorecardMode:    "stub",
		ByteGate:         byteGateAllowButLog,
	}

	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	first := fw.describePolicy()
	firstNames := policyRuleOrder(first)

	for i := 2; i <= 50; i++ {
		fw, err := NewFirewall(cfg)
		if err != nil {
			t.Fatalf("NewFirewall #%d: %v", i, err)
		}
		v := fw.describePolicy()
		if v.Digest != first.Digest {
			t.Fatalf("policy digest changed between identical constructions (#%d): %q vs %q — "+
				"something in the policy is iterated in a non-deterministic order", i, v.Digest, first.Digest)
		}
		if got := policyRuleOrder(v); got != firstNames {
			t.Fatalf("rule ORDER changed between identical constructions (#%d).\nfirst: %s\nnow:   %s",
				i, firstNames, got)
		}
	}

	// Guard against the assertion being vacuous: if the policy ever described no rules,
	// every comparison above would trivially hold.
	if firstNames == "" {
		t.Fatal("policy described no rules, so the comparisons above prove nothing")
	}
}

// policyRuleOrder flattens a policy into an order-sensitive string. Order-SENSITIVE is the
// point: comparing sets would pass on a shuffled ruleset, and in an ordered engine a
// shuffle changes verdicts.
func policyRuleOrder(v PolicyView) string {
	s := ""
	for _, c := range v.Chains {
		s += c.Name + "{"
		for _, r := range c.Rules {
			s += r.Name + ";"
		}
		s += "default=" + c.DefaultAction + "}"
	}
	return s
}
