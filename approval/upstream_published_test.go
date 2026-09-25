package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// PyPI has no per-release timestamp. npm's packument carries `time[version]`, which is
// authoritative and unambiguous; PyPI's JSON carries a per-FILE upload_time, and the
// files of one release are not always uploaded together. Measured on the latest release
// of each, at the time this was written:
//
//	pyyaml        73 files, spanning 3 days 22:56
//	numpy         66 files, spanning 3m18s
//	cryptography  46 files, spanning 1m42s
//	requests       2 files, spanning 1s
//
// So "when did this release appear" has to be the EARLIEST of its files. The code used
// to read urls[0] on the stated ground that "any entry carries the release's publication
// moment", which the pyyaml row falsifies.
//
// urls[0] was in fact the earliest in every package sampled, so this is a correctness
// tidy-up rather than a live defect — but the ordering of that array is not documented,
// and the assertions below hold whatever order PyPI chooses.
func TestPypiPublishedAtIsTheEarliestFileUpload(t *testing.T) {
	const (
		earliest = "2025-09-21T22:35:46.000000Z"
		middle   = "2025-09-23T09:00:00.000000Z"
		latest   = "2025-09-25T21:31:46.000000Z"
	)

	for _, tc := range []struct {
		name  string
		times []string
	}{
		// The shape PyPI happens to serve today: earliest first.
		{"earliest first", []string{earliest, middle, latest}},
		// The shape nothing guarantees it will not serve tomorrow. This is the case
		// urls[0] gets wrong, and it is why the minimum is taken explicitly.
		{"earliest last", []string{latest, middle, earliest}},
		{"earliest in the middle", []string{latest, earliest, middle}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				files := ""
				for i, ts := range tc.times {
					if i > 0 {
						files += ","
					}
					files += fmt.Sprintf(`{"upload_time_iso_8601":%q}`, ts)
				}
				fmt.Fprintf(w, `{"info":{"version":"6.0.2"},"releases":{"6.0.2":[]},"urls":[%s]}`, files)
			}))
			defer srv.Close()

			up := &pypiUpstream{base: srv.URL, http: srv.Client()}
			h, ok, err := up.Fetch("pyyaml")
			if err != nil || !ok {
				t.Fatalf("Fetch: ok=%v err=%v", ok, err)
			}

			want, _ := time.Parse(time.RFC3339, earliest)
			if !h.PublishedAt.Equal(want) {
				t.Errorf("PublishedAt = %s, want %s (the earliest of the release's files).\n"+
					"  Reading urls[0] instead makes the published date depend on an array\n"+
					"  order PyPI does not document, and a release whose files were uploaded\n"+
					"  days apart then shows the wrong moment to the operator.",
					h.PublishedAt.Format(time.RFC3339), want.Format(time.RFC3339))
			}
		})
	}
}

// TestPypiPublishedAtSurvivesAnUnparseableStamp is the control on the skip: one bad
// entry must not hide the good ones, and must not leave the field zero.
func TestPypiPublishedAtSurvivesAnUnparseableStamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"info":{"version":"1.0"},"releases":{"1.0":[]},"urls":[`+
			`{"upload_time_iso_8601":"not-a-timestamp"},`+
			`{"upload_time_iso_8601":"2025-01-02T03:04:05.000000Z"}]}`)
	}))
	defer srv.Close()

	up := &pypiUpstream{base: srv.URL, http: srv.Client()}
	h, ok, err := up.Fetch("x")
	if err != nil || !ok {
		t.Fatalf("Fetch: ok=%v err=%v", ok, err)
	}
	want, _ := time.Parse(time.RFC3339, "2025-01-02T03:04:05Z")
	if !h.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v — an unparseable stamp on one file must be "+
			"skipped, not allowed to suppress the release's real date",
			h.PublishedAt, want)
	}
}

// TestPypiPublishedAtIsZeroWithNoFiles keeps the assertions above honest: the field is
// omitempty, and a release with no files must leave it unset rather than defaulting to
// something that renders as a date.
func TestPypiPublishedAtIsZeroWithNoFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"info":{"version":"1.0"},"releases":{"1.0":[]},"urls":[]}`)
	}))
	defer srv.Close()

	up := &pypiUpstream{base: srv.URL, http: srv.Client()}
	h, _, err := up.Fetch("x")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !h.PublishedAt.IsZero() {
		t.Errorf("PublishedAt = %v for a release with no files, want the zero time", h.PublishedAt)
	}
}
