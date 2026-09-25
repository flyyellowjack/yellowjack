package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// #152: the npm harvest STREAMS the packument instead of decoding it, because the
// document reaches 67 MB and this process has 128 Mi.
//
// Four properties, each with a control:
//
//	1. it gives the same answer the whole-document decode gave   (differential)
//	2. memory does not track the document's size                 (control: the old decode does)
//	3. key order does not change the answer                      (and the fallback is bounded)
//	4. a hostile document is refused without exhausting memory   (three different shapes)

// referenceNpmHarvest is the whole-document decode this file replaces, kept verbatim as
// the oracle for the differential. It is the definition of "the right answer" for any
// document small enough to decode.
func referenceNpmHarvest(doc []byte) (upstreamHarvest, error) {
	var d struct {
		DistTags map[string]string `json:"dist-tags"`
		Time     map[string]string `json:"time"`
		Versions map[string]struct {
			Deprecated json.RawMessage `json:"deprecated"`
		} `json:"versions"`
		Maintainers []struct{} `json:"maintainers"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return upstreamHarvest{}, err
	}
	h := upstreamHarvest{LatestVersion: d.DistTags["latest"], VersionCount: len(d.Versions), Maintainers: len(d.Maintainers)}
	if h.LatestVersion != "" {
		if t, err := time.Parse(time.RFC3339, d.Time[h.LatestVersion]); err == nil {
			h.PublishedAt = t
		}
		if v, ok := d.Versions[h.LatestVersion]; ok {
			h.Deprecated = normalizeDeprecated(v.Deprecated)
		}
	}
	return h, nil
}

// esc is the two characters that begin a JSON unicode escape, built from code points so
// the sequence never appears literally in this file.
var esc = string([]rune{92, 117})

func TestStreamingHarvestMatchesTheWholeDocumentDecode(t *testing.T) {
	docs := map[string]string{
		"the registry's usual order": `{"_id":"p","name":"p","dist-tags":{"latest":"2.0.0","next":"3.0.0-rc"},
			"versions":{"1.0.0":{"name":"p","dist":{"tarball":"x"}},"2.0.0":{"deprecated":"use q instead"},"3.0.0-rc":{}},
			"time":{"created":"2020-01-01T00:00:00Z","1.0.0":"2020-01-02T00:00:00Z","2.0.0":"2021-06-07T08:09:10.123Z"},
			"maintainers":[{"name":"a"},{"name":"b"}],"readme":"hi"}`,
		"dist-tags LAST": `{"versions":{"1.0.0":{},"2.0.0":{"deprecated":"old"}},"time":{"2.0.0":"2021-06-07T08:09:10Z"},
			"maintainers":[{}],"dist-tags":{"latest":"2.0.0"}}`,
		"time before versions":                       `{"time":{"1.0.0":"2020-01-02T00:00:00Z"},"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`,
		"deprecated as a bare true":                  `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"deprecated":true}}}`,
		"deprecated false (un-deprecated)":           `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"deprecated":false}}}`,
		"deprecated on a version that is NOT latest": `{"dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{"deprecated":"x"},"2.0.0":{}}}`,
		"no latest tag at all":                       `{"dist-tags":{"beta":"1.0.0-b"},"versions":{"1.0.0-b":{}},"time":{"1.0.0-b":"2020-01-02T00:00:00Z"}}`,
		"null members":                               `{"dist-tags":{"latest":"1.0.0"},"versions":null,"time":null,"maintainers":null}`,
		"missing members":                            `{"name":"p"}`,
		"an unparseable timestamp":                   `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}},"time":{"1.0.0":"yesterday"}}`,
		// Everything below is aimed at the SKIPPER: content that looks structural and is not.
		"structure-shaped bytes inside skipped strings": `{"readme":"a \" } ] { [ , : \\","x":"\\\\","dist-tags":{"latest":"1.0.0"},
			"versions":{"1.0.0":{"description":"}}}]]]\"","deprecated":"real \"reason\" \\ here"}}}`,
		// The KEY "1.0.0" is spelled with a JSON unicode escape for its middle zero, and the
		// message uses escapes including a surrogate pair. The escapes are assembled at
		// runtime from `esc` so that no editor or tool can "helpfully" decode them in this
		// source file -- which is exactly what happened to the first version of this
		// fixture, leaving a test named "escaped keys" that contained none.
		"escaped keys and unicode": `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.` + esc + `0030.0":{"deprecated":"caf` + esc + `00e9 ` + esc + `d83d` + esc + `de00"}},
			"time":{"1.` + esc + `0030.0":"2020-01-02T00:00:00Z"}}`,
		"deep nesting and every scalar kind in skipped values": `{"junk":[[[[{"a":[1,-2.5e+10,true,false,null,{"b":[]}]}]]]],"n":0,
			"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"n":1e9,"t":true,"z":null,"deprecated":"d"}}}`,
		"whitespace everywhere": " {\n\t\"dist-tags\" :\r\n { \"latest\" : \"1.0.0\" } ,\n \"versions\" : { \"1.0.0\" : { } } , \"maintainers\" : [ ] } \n",
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			want, err := referenceNpmHarvest([]byte(doc))
			if err != nil {
				t.Fatalf("the ORACLE rejects this fixture (%v), so it cannot arbitrate", err)
			}
			got, err := harvestNpmPackument(strings.NewReader(doc))
			if err != nil {
				t.Fatalf("streaming harvest failed on a document the whole-document decode accepts: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("harvests differ\n streaming: %+v\n reference: %+v", got, want)
			}
		})
	}
	// The escaped-key fixture must actually CONTAIN escapes, and decoding them must be what
	// connects the key to `latest` -- otherwise the oracle and the subject agree on an
	// empty answer and the differential above is satisfied by two wrongs.
	escaped := docs["escaped keys and unicode"]
	if strings.Count(escaped, esc) != 5 {
		t.Fatalf("the escaped-key fixture holds %d unicode escapes, want 5; something decoded them in the source", strings.Count(escaped, esc))
	}
	if h, _ := harvestNpmPackument(strings.NewReader(escaped)); h.PublishedAt.IsZero() || !strings.HasPrefix(h.Deprecated, "caf") {
		t.Fatalf("an ESCAPED key was not matched to the latest version: %+v", h)
	}

	// ANTI-VACUITY for the differential itself: an oracle and a subject that both return
	// the zero value agree perfectly. At least one fixture must produce every field.
	full, _ := harvestNpmPackument(strings.NewReader(docs["the registry's usual order"]))
	if full.LatestVersion != "2.0.0" || full.VersionCount != 3 || full.Maintainers != 2 ||
		full.Deprecated != "use q instead" || full.PublishedAt.Year() != 2021 {
		t.Fatalf("the richest fixture did not exercise every field: %+v", full)
	}
}

// packumentStream GENERATES a registry-shaped packument on the fly, so a test can feed the
// harvester tens of megabytes without the test itself holding them -- which would make a
// memory assertion meaningless.
//
// It must also not ALLOCATE, and the first version did: fmt.Sprintf and strings.Repeat per
// part, plus a []byte conversion, came to about four bytes of garbage per byte emitted.
// TotalAlloc counts the generator's garbage exactly like the harvester's, so the first run
// of this test "measured" a constant-memory reader allocating 213 MB for a 47 MB document.
// Every part is now appended into one reused scratch buffer.
type packumentStream struct {
	versions, bodyBytes int
	distTagsLast        bool
	i                   int // next part to emit
	buf                 []byte
	scratch             []byte
	body                []byte // the filler readme, built once
}

func (p *packumentStream) latest() string { return "1.0." + strconv.Itoa(p.versions-1) }

// part returns the i-th chunk of the document, or nil when it is complete. The slice is
// only valid until the next call.
func (p *packumentStream) part(i int) []byte {
	if p.body == nil {
		p.body = []byte(strings.Repeat("r", p.bodyBytes))
	}
	out := p.scratch[:0]
	tags := func(dst []byte) []byte {
		dst = append(dst, "\"dist-tags\":{\"latest\":\""...)
		dst = append(dst, p.latest()...)
		return append(dst, "\"}"...)
	}
	switch {
	case i == 0:
		out = append(out, "{\"name\":\"big\","...)
		if !p.distTagsLast {
			out = append(tags(out), ',')
		}
		out = append(out, "\"versions\":{"...)
	case i <= p.versions:
		v := i - 1
		if v > 0 {
			out = append(out, ',')
		}
		out = append(out, "\"1.0."...)
		out = strconv.AppendInt(out, int64(v), 10)
		out = append(out, "\":{"...)
		if v == p.versions-1 {
			out = append(out, "\"deprecated\":\"moved to bigger\","...)
		}
		out = append(out, "\"dist\":{\"tarball\":\"t\"},\"readme\":\""...)
		out = append(out, p.body...)
		out = append(out, "\"}"...)
	case i == p.versions+1:
		out = append(out, "},\"time\":{\"created\":\"2019-01-01T00:00:00Z\""...)
	case i <= 2*p.versions+1:
		out = append(out, ",\"1.0."...)
		out = strconv.AppendInt(out, int64(i-p.versions-2), 10)
		out = append(out, "\":\"2024-03-04T05:06:07Z\""...)
	case i == 2*p.versions+2:
		out = append(out, "},\"maintainers\":[{\"name\":\"a\"},{\"name\":\"b\"},{\"name\":\"c\"}]"...)
		if p.distTagsLast {
			out = tags(append(out, ','))
		}
		out = append(out, '}')
	default:
		return nil
	}
	p.scratch = out
	return out
}

func (p *packumentStream) Read(out []byte) (int, error) {
	for len(p.buf) == 0 {
		next := p.part(p.i)
		if next == nil {
			return 0, io.EOF
		}
		p.i++
		p.buf = next
	}
	n := copy(out, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

// allocatedDuring reports the bytes ALLOCATED while fn ran. TotalAlloc is cumulative and
// never decreases, so it is an upper bound on peak heap -- a stricter thing to stay under
// than the peak itself, and not at the mercy of when the collector happens to run.
func allocatedDuring(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestAHugePackumentHarvestsWithoutHoldingIt(t *testing.T) {
	// ~6,000 versions of ~8 KB: the shape and scale of the documents that were unreadable
	// (renovate: 5,556 versions, 66.9 MB).
	const versions, body = 6000, 8 << 10
	size := int64(0)
	for s, i := (&packumentStream{versions: versions, bodyBytes: body}), 0; ; i++ {
		part := s.part(i)
		if part == nil {
			break
		}
		size += int64(len(part))
	}
	if size < 40<<20 {
		t.Fatalf("the generated packument is only %d MB; it must dwarf the old 8 MB cap to mean anything", size>>20)
	}

	var h upstreamHarvest
	var err error
	used := allocatedDuring(func() {
		h, err = harvestNpmPackument(&packumentStream{versions: versions, bodyBytes: body})
	})
	if err != nil {
		t.Fatalf("a %d MB packument was refused: %v. This is the document class #152 exists to read", size>>20, err)
	}
	want := upstreamHarvest{LatestVersion: "1.0.5999", VersionCount: versions, Maintainers: 3,
		Deprecated: "moved to bigger", PublishedAt: time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("harvest of the large document:\n got  %+v\n want %+v", h, want)
	}
	// The whole point: one sixteenth of the document, and the generator contributes nothing.
	if limit := uint64(size / 16); used > limit {
		t.Errorf("harvesting a %d MB document allocated %d MB; memory is tracking the document's size, "+
			"which is what a 128 Mi process cannot afford", size>>20, used>>20)
	}
	t.Logf("%d MB packument, %d versions: %d KB allocated in total", size>>20, versions, used>>10)
}

// TestTheWholeDocumentDecodeDoesTrackSize is the CONTROL for the memory assertion above:
// the same measurement, on the same generated document, must be ABLE to see a reader that
// holds the document -- or a small number there proves nothing about this one.
//
// What is measured is the READ PATH the service actually used (a json.Decoder over the
// body), because that is where the document was held. The first version of this control
// measured json.Unmarshal on a buffer read beforehand and saw 210 KB for a 5 MB document:
// the narrow projection allocates almost nothing, the BUFFERING is what costs, and the
// buffering had been done outside the measurement.
func TestTheWholeDocumentDecodeDoesTrackSize(t *testing.T) {
	const versions, body = 600, 8 << 10 // ~5 MB
	var size int64
	for g, i := (&packumentStream{versions: versions, bodyBytes: body}), 0; ; i++ {
		part := g.part(i)
		if part == nil {
			break
		}
		size += int64(len(part))
	}
	decoded := allocatedDuring(func() {
		var d struct {
			DistTags map[string]string `json:"dist-tags"`
		}
		_ = json.NewDecoder(&packumentStream{versions: versions, bodyBytes: body}).Decode(&d)
	})
	streamed := allocatedDuring(func() {
		_, _ = harvestNpmPackument(&packumentStream{versions: versions, bodyBytes: body})
	})
	if decoded < uint64(size) {
		t.Fatalf("decoding a %d KB document allocated only %d KB, so this measurement cannot tell "+
			"holding from streaming and the assertion in the test above is unproven", size>>10, decoded>>10)
	}
	if streamed*8 > decoded {
		t.Errorf("streaming allocated %d KB against the decode's %d KB; expected a small fraction", streamed>>10, decoded>>10)
	}
	t.Logf("%d KB document: whole-document decode allocated %d KB, streaming %d KB", size>>10, decoded>>10, streamed>>10)
}

func TestKeyOrderDoesNotChangeTheHarvest(t *testing.T) {
	usual, err := harvestNpmPackument(&packumentStream{versions: 300, bodyBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := harvestNpmPackument(&packumentStream{versions: 300, bodyBytes: 64, distTagsLast: true})
	if err != nil {
		t.Fatalf("a packument with `dist-tags` LAST was refused: %v. The usual order is an observation about "+
			"one registry, not a contract", err)
	}
	if !reflect.DeepEqual(usual, reordered) || usual.Deprecated == "" || usual.PublishedAt.IsZero() {
		t.Errorf("key order changed the harvest, or the fixture exercised nothing:\n usual     %+v\n reordered %+v", usual, reordered)
	}
}

// endless emits prefix, then repeats unit forever. unit APPENDS the n-th repetition to dst
// (so a unit can be made distinct) into a buffer that is reused -- allocation-free, for the
// reason packumentStream is.
type endless struct {
	prefix  string
	unit    func(dst []byte, n int) []byte
	n       int
	started bool
	buf     []byte
	scratch []byte
	read    int64
}

func (e *endless) Read(out []byte) (int, error) {
	if !e.started {
		e.started = true
		e.buf = []byte(e.prefix)
	}
	for len(e.buf) == 0 {
		e.scratch = e.unit(e.scratch[:0], e.n)
		e.buf = e.scratch
		e.n++
	}
	n := copy(out, e.buf)
	e.buf = e.buf[n:]
	e.read += int64(n)
	return n, nil
}

// numbered returns a unit of the form  <before><n><after>.
func numbered(before, after string) func([]byte, int) []byte {
	return func(dst []byte, n int) []byte {
		dst = append(dst, before...)
		dst = strconv.AppendInt(dst, int64(n), 10)
		return append(dst, after...)
	}
}

func TestAHostilePackumentIsRefusedWithoutExhaustingMemory(t *testing.T) {
	for _, c := range []struct {
		name      string
		doc       *endless
		mostBytes int64 // it must give up before reading more than this
	}{
		// Distinct tiny keys BEFORE `dist-tags`: the shape that grows a map far faster
		// than it grows the byte count. The byte budget alone would let this hold ~23
		// million entries.
		{"endless distinct versions, latest unknown",
			&endless{prefix: `{"versions":{"0":{}`, unit: numbered(`,"1.0.`, `":{"deprecated":"x"}`)},
			64 << 20},
		{"endless distinct time entries, latest unknown",
			&endless{prefix: `{"time":{"0":"t"`, unit: numbered(`,"1.0.`, `":"2024-03-04T05:06:07Z"`)},
			64 << 20},
		// The usual order, so nothing is retained -- only COUNTED. Bounded by the count.
		{"endless versions, latest known",
			&endless{prefix: `{"dist-tags":{"latest":"9"},"versions":{"0":{}`, unit: func(dst []byte, _ int) []byte { return append(dst, `,"1":{}`...) }},
			64 << 20},
	} {
		t.Run(c.name, func(t *testing.T) {
			var err error
			used := allocatedDuring(func() { _, err = harvestNpmPackument(c.doc) })
			if !errors.Is(err, errBodyTooLarge) {
				t.Fatalf("got %v, want errBodyTooLarge: a document this service gives up on is TOO LARGE, which has "+
					"its own marker; anything else renders as 'registry unreachable'", err)
			}
			if c.doc.read > c.mostBytes {
				t.Errorf("read %d MB before giving up, want under %d MB", c.doc.read>>20, c.mostBytes>>20)
			}
			// TotalAlloc is cumulative -- it counts every intermediate map as it grows --
			// so it over-states the peak by about 2x. 48 MB here is a peak near 24 MB.
			if used > 48<<20 {
				t.Errorf("allocated %d MB (cumulative) before giving up; the process has 128 Mi", used>>20)
			}
			t.Logf("gave up after %d KB read, %d KB allocated: %v", c.doc.read>>10, used>>10, err)
		})
	}
}

// TestOneEnormousValueIsSkippedInConstantMemory is the case encoding/json cannot handle:
// Decoder.Token buffers a whole string, so a single huge string is bounded only by the
// byte budget. The skimmer never holds a value it was not asked to keep.
var fourKBofA = strings.Repeat("A", 4096)

func TestOneEnormousValueIsSkippedInConstantMemory(t *testing.T) {
	const huge = 64 << 20
	doc := io.MultiReader(
		strings.NewReader(`{"readme":"`),
		io.LimitReader(&endless{unit: func(dst []byte, _ int) []byte { return append(dst, fourKBofA...) }}, huge),
		strings.NewReader(`","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`),
	)
	var h upstreamHarvest
	var err error
	used := allocatedDuring(func() { h, err = harvestNpmPackument(doc) })
	if err != nil || h.LatestVersion != "1.0.0" || h.VersionCount != 1 {
		t.Fatalf("a document with one %d MB string: harvest %+v, err %v", huge>>20, h, err)
	}
	if used > 8<<20 {
		t.Errorf("skipping a %d MB string allocated %d MB; a skipped value must cost nothing", huge>>20, used>>20)
	}
}

func TestATruncatedOrNonJSONPackumentIsAnErrorNotAnEmptyHarvest(t *testing.T) {
	for name, doc := range map[string]string{
		"cut off inside versions": `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dep`,
		"cut off inside a string": `{"readme":"never ends`,
		"an HTML error page":      `<html><body>502 Bad Gateway</body></html>`,
		"empty":                   ``,
		"a bare array":            `[1,2,3]`,
	} {
		t.Run(name, func(t *testing.T) {
			h, err := harvestNpmPackument(strings.NewReader(doc))
			if err == nil {
				t.Fatalf("got a harvest %+v and no error. Rendered, that is a real package with zero versions", h)
			}
			if errors.Is(err, errBodyTooLarge) {
				t.Errorf("a short broken document was reported as TOO LARGE: %v", err)
			}
		})
	}
}

// TestAMillionNestedArraysCostNoStack: depth is a counter, not recursion.
func TestAMillionNestedArraysCostNoStack(t *testing.T) {
	const depth = 1 << 20
	doc := `{"junk":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `,"dist-tags":{"latest":"1.0.0"}}`
	h, err := harvestNpmPackument(strings.NewReader(doc))
	if err != nil || h.LatestVersion != "1.0.0" {
		t.Fatalf("harvest %+v, err %v", h, err)
	}
}

// TestTheHarvestTimeoutFitsInsideTheConsolesTimeout pins an ordering across two binaries
// that share no constant: the console gives this service a fixed time to answer, and a
// harvest allowed to outlive its caller is work nobody is waiting for.
func TestTheHarvestTimeoutFitsInsideTheConsolesTimeout(t *testing.T) {
	src, err := os.ReadFile("../console/main.go")
	if err != nil {
		t.Fatalf("read the console's client construction: %v", err)
	}
	found := regexp.MustCompile(`http\.Client\{Timeout: (\d+) \* time\.Second\}`).FindAllSubmatch(src, -1)
	if len(found) == 0 {
		t.Fatal("found no `http.Client{Timeout: N * time.Second}` in console/main.go; this test is reading nothing")
	}
	for _, m := range found {
		n, _ := strconv.Atoi(string(m[1]))
		console := time.Duration(n) * time.Second
		if upstreamFetchTimeout >= console {
			t.Errorf("a harvest may run %s but the console stops waiting after %s", upstreamFetchTimeout, console)
		}
		if console-upstreamFetchTimeout < time.Second {
			t.Errorf("only %s is left for the rest of /v1/packages after a %s harvest", console-upstreamFetchTimeout, upstreamFetchTimeout)
		}
	}
}

// TestASlowRegistryIsReportedAsTimedOutNotUnreachable: once the read streams, the largest
// packuments are bounded by TIME on a slow link, and a deadline that fires mid-body -- after
// the registry has plainly been reached -- must not be reported as a connectivity failure.
func TestASlowRegistryIsReportedAsTimedOutNotUnreachable(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Headers and the start of a perfectly good document arrive at once; the rest
		// never does. This is the mid-body case, not a slow connect.
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"dist-tags":{"latest":"1.0.0"},"versions":{`)
		w.(http.Flusher).Flush()
		<-release
	}))
	t.Cleanup(func() { close(release); slow.Close() })
	client := &http.Client{Timeout: 300 * time.Millisecond}

	if h, avail := harvestUpstream(&npmUpstream{base: slow.URL, http: client}, "big"); avail != availUpstreamTimedOut || h != nil {
		t.Errorf("a registry that stalls mid-document gave (%v, %q), want (nil, %q)", h, avail, availUpstreamTimedOut)
	}

	// CONTROLS: the split must not swallow its neighbours. A refused connection is still
	// unreachable, and a prompt answer is still present.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	if _, avail := harvestUpstream(&npmUpstream{base: deadURL, http: client}, "big"); avail != availUpstreamUnreachable {
		t.Errorf("a REFUSED connection gave %q, want %q: nothing timed out, nothing answered", avail, availUpstreamUnreachable)
	}
	f, _ := npmStub(t, http.StatusOK, `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`)
	if _, avail := harvestUpstream(f, "ok"); avail != availPresent {
		t.Errorf("a prompt answer gave %q, want %q", avail, availPresent)
	}
}
