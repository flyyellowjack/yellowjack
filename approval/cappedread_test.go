package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #139 on the approval side: a registry document over the read cap must be reported as
// THAT, not as an unreachable registry.
//
// Why it is worth a test and not just a fix: measured 2026-09-20, ten of twenty sampled
// npm packages (next, vite, typescript, npm, renovate ...) have a full packument over this
// service's 8 MB cap. For every one of them the developer lookup said "we could not reach
// the registry" -- a connectivity diagnosis for a registry that had answered perfectly
// well, about the packages a developer is most likely to look up.
//
// Each case is a WELL-FORMED document that is merely large, so the only thing wrong with
// it is its size; the control beside it is the same document under the cap, which proves
// the refusal is the cap and not the fixture.

// padTo returns n bytes of JSON-string-safe filler.
func padTo(n int) string { return strings.Repeat("A", n) }

func TestAnOversizeRegistryDocumentIsNotReportedAsUnreachable(t *testing.T) {
	const over = upstreamMaxBytes + 1024

	npmDoc := func(pad int) string {
		return `{"dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":"2024-01-02T03:04:05Z"},` +
			`"versions":{"1.0.0":{}},"maintainers":[{}],"readme":"` + padTo(pad) + `"}`
	}
	pypiDoc := func(pad int) string {
		return `{"info":{"version":"2.31.0","yanked":false,"yanked_reason":null,"description":"` + padTo(pad) + `"},` +
			`"releases":{"2.31.0":[]},"urls":[{"upload_time_iso_8601":"2023-05-22T15:12:42.123456Z"}]}`
	}
	mavenDoc := func(pad int) string {
		return `<metadata><groupId>com.google.guava</groupId><artifactId>guava</artifactId>` +
			`<versioning><release>33.0.0-jre</release><versions><version>33.0.0-jre</version></versions>` +
			`</versioning><!-- ` + padTo(pad) + ` --></metadata>`
	}

	// npm is NOT in the table below any more, and that is the point of #152: its harvest
	// streams, so a well-formed packument over the old 8 MB cap is simply READ. The
	// inversion is asserted rather than dropped, because "a big npm document is refused"
	// was this test's claim for one merge request and must not quietly survive as a belief.
	t.Run("npm packument over the old cap is now READ", func(t *testing.T) {
		f, _ := npmStub(t, http.StatusOK, npmDoc(over))
		h, avail := harvestUpstream(f, "bigpkg")
		if avail != availPresent || h == nil || h.LatestVersion != "1.0.0" || h.VersionCount != 1 || h.PublishedAt.IsZero() {
			t.Fatalf("a well-formed %d MB packument gave (%+v, %q), want a present, complete harvest", over>>20, h, avail)
		}
	})
	// What IS too large for npm now is a document the stream gives up on, and it must
	// reach the same marker through the real fetch path -- not "unreachable".
	t.Run("npm packument the stream gives up on", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`{"versions":{"0":{}`)
		for i := 0; b.Len() < 2*npmMaxRetainedBytes; i++ {
			fmt.Fprintf(&b, `,"1.0.%d":{"deprecated":"this version is retained because latest is not known yet"}`, i)
		}
		b.WriteString(`},"dist-tags":{"latest":"1.0.0"}}`)
		f, _ := npmStub(t, http.StatusOK, b.String())
		if h, avail := harvestUpstream(f, "hostile"); avail != availUpstreamTooLarge || h != nil {
			t.Fatalf("got (%v, %q), want (nil, %q)", h, avail, availUpstreamTooLarge)
		}
	})

	for _, c := range []struct {
		name, pkg string
		fetcher   func(body string) upstreamFetcher
		doc       func(pad int) string
	}{
		{"PyPI project JSON", "bigpkg",
			func(b string) upstreamFetcher { f, _, _ := pypiStub(t, http.StatusOK, b); return f }, pypiDoc},
		{"Maven metadata", "com.google.guava:guava",
			func(b string) upstreamFetcher { f, _ := newMavenStub(t, b); return f }, mavenDoc},
	} {
		t.Run(c.name, func(t *testing.T) {
			// CONTROL FIRST: the same document under the cap is a normal, present result.
			// Without it, "too large" below could be produced by a fixture this fetcher
			// cannot parse at any size.
			if h, avail := harvestUpstream(c.fetcher(c.doc(64)), c.pkg); avail != availPresent || h == nil {
				t.Fatalf("CONTROL: the under-cap document gave (%v, %q), want a present harvest; "+
					"the oversize assertion below would prove nothing", h, avail)
			}

			h, avail := harvestUpstream(c.fetcher(c.doc(over)), c.pkg)
			if h != nil {
				t.Errorf("an over-cap document produced a harvest %+v. For Maven this is the silent "+
					"TRUNCATION io.ReadAll(io.LimitReader(...)) performs: a prefix was parsed as if "+
					"it were the document", h)
			}
			if avail != availUpstreamTooLarge {
				t.Errorf("availability = %q, want %q. The registry ANSWERED; %q tells the reader to "+
					"go and debug their network", avail, availUpstreamTooLarge, availUpstreamUnreachable)
			}
		})
	}
}

// TestAMalformedDocumentIsStillNotTooLarge is the other side of the split: "too large"
// must not become the new catch-all. A short, broken document is a registry problem.
func TestAMalformedDocumentIsStillNotTooLarge(t *testing.T) {
	f, _ := npmStub(t, http.StatusOK, `{"dist-tags":{"latest":`)
	if _, avail := harvestUpstream(f, "broken"); avail != availUpstreamUnreachable {
		t.Errorf("a truncated 24-byte document gave %q, want %q", avail, availUpstreamUnreachable)
	}
}

// TestCappedReadHelpers pins the two helpers directly, including the boundary the
// Maven fix depends on: under the cap is whole, at or over it is refused -- never a prefix.
func TestCappedReadHelpers(t *testing.T) {
	if b, err := readCapped(strings.NewReader("1234567"), 8); err != nil || string(b) != "1234567" {
		t.Errorf("a body under the cap: got (%q, %v), want it whole", b, err)
	}
	for _, body := range []string{"12345678", "123456789"} {
		if b, err := readCapped(strings.NewReader(body), 8); !errors.Is(err, errBodyTooLarge) || b != nil {
			t.Errorf("a %d-byte body against a cap of 8: got (%q, %v), want errBodyTooLarge and NO bytes -- "+
				"returning the prefix is the truncation this helper exists to end. (A body that exactly "+
				"FILLS the cap is refused on purpose: telling it from an overrun costs a byte past the cap.)",
				len(body), b, err)
		}
	}

	var v map[string]any
	if err := decodeCapped(strings.NewReader(`{"a":"`+padTo(64)+`"}`), 16, &v); !errors.Is(err, errBodyTooLarge) {
		t.Errorf("an over-cap JSON document: got %v, want errBodyTooLarge", err)
	}
	if err := decodeCapped(strings.NewReader(`{"a":`), 1024, &v); err == nil || errors.Is(err, errBodyTooLarge) {
		t.Errorf("a short malformed document: got %v, want a plain decode error", err)
	}
}

// TestTheFourNoDataMarkersAreDistinct extends the discriminator in upstream_test.go to
// the marker #139 added. A harvestUpstream returning one string for everything would
// satisfy every assertion that happened to expect that string.
func TestTheFourNoDataMarkersAreDistinct(t *testing.T) {
	seen := map[string]bool{
		availNotCollected: true, availNotInRegistry: true,
		availUpstreamUnreachable: true, availUpstreamTooLarge: true,
	}
	if len(seen) != 4 {
		t.Fatal("the four no-data markers are not four distinct strings")
	}
	// The console switches on this literal (console/lookup.go) and the two binaries share
	// no constant, so the spelling is a wire contract. Pinned here; the console pins its
	// half by deriving every marker from this package's source.
	if availUpstreamTooLarge != "registry-metadata-too-large-to-read" {
		t.Errorf("availUpstreamTooLarge = %q; the console's explanation is keyed on the old spelling", availUpstreamTooLarge)
	}
}

// The two ingest handlers (#139). An oversize heartbeat used to be answered "invalid JSON
// body", and the consequence is the one maxHealthBytes' own comment warns about: the
// replica's reported_at stops advancing and a healthy firewall reads as DEAD. The status
// and the text must say which failure it was.
func TestAnOversizeIngestBodyIsA413ThatSaysSo(t *testing.T) {
	post := func(path, body string) (int, string) {
		srv := &server{store: newMemStore()}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return rec.Code, rec.Body.String()
	}
	beat := func(pad int) string {
		return `{"instance":"fw-1","ecosystem":"npm","audit_dropped":0,"flow_dropped":0,"pad":"` + padTo(pad) + `"}`
	}

	// CONTROL: a VALID beat just under the cap is accepted. Without it the 413 below
	// could come from a fixture the handler rejects at any size.
	if code, body := post("/v1/health", beat(maxHealthBytes-256)); code != http.StatusAccepted {
		t.Fatalf("CONTROL: a valid beat under the cap = %d (%s), want 202", code, body)
	}
	code, body := post("/v1/health", beat(maxHealthBytes))
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversize heartbeat = %d, want 413. A 400 tells the sender its JSON is broken", code)
	}
	if !strings.Contains(body, "exceeds") || strings.Contains(body, "invalid JSON") {
		t.Errorf("the refusal must name the size, not the syntax; got %q", body)
	}
	// And malformed stays malformed: 413 must not become the catch-all.
	if code, _ := post("/v1/health", `{"instance":`); code != http.StatusBadRequest {
		t.Errorf("a short malformed heartbeat = %d, want 400", code)
	}

	flow := `{"instance":"fw-1","packages":[],"sources":[],"pad":"` + padTo(maxFlowBatchBytes) + `"}`
	if code, body := post("/v1/flow", flow); code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "exceeds") {
		t.Errorf("an oversize flow batch = %d %q, want 413 naming the size", code, body)
	}
}
