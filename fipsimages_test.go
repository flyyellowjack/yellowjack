package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D374: every container we publish is built against the certified FIPS 140-3 Go
// Cryptographic Module. The Dockerfiles are the only place that is decided, so this reads
// them: each one that builds a Go binary must declare the GOFIPS140 build argument with a
// real module as its default, pass it to `go build`, and copy in the shared banner package.
// A new service Dockerfile, or an edit that drops the setting, fails here instead of
// shipping a non-FIPS image nobody notices. Test fixtures under e2e/ are not published and
// are skipped.

var (
	goBuildLine  = regexp.MustCompile(`(?m)^RUN .*\bgo build\b.*$`)
	fipsArgLine  = regexp.MustCompile(`(?m)^ARG GOFIPS140=(\S+)\s*$`)
	fipsCopyLine = regexp.MustCompile(`(?m)^COPY fipsmode/ \./fipsmode/\s*$`)
)

// publishedDockerfiles is every Dockerfile in the tree outside e2e/, derived from the
// filesystem so a new service is covered without anyone listing it.
func publishedDockerfiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Hidden directories include CI's module cache (.gocache/ inside the checkout),
			// which holds other projects' Dockerfiles.
			if rel != "." && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			switch rel {
			case "e2e", "reference", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "Dockerfile" {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking for Dockerfiles: %v", err)
	}
	return out
}

// fipsProblems returns what is wrong with one Dockerfile's FIPS setup, or nil.
func fipsProblems(src string) []string {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	builds := goBuildLine.FindAllString(src, -1)
	if len(builds) == 0 {
		return nil // builds no Go binary (nothing of ours to put in FIPS mode)
	}
	var probs []string
	m := fipsArgLine.FindStringSubmatch(src)
	switch {
	case m == nil:
		probs = append(probs, "no `ARG GOFIPS140=<module>` line")
	case m[1] == "off" || m[1] == "" || m[1] == `""`:
		probs = append(probs, "GOFIPS140 defaults to "+m[1]+", so the published image is not FIPS")
	}
	for _, b := range builds {
		if !strings.Contains(b, "GOFIPS140=$GOFIPS140") {
			probs = append(probs, "a `go build` does not pass GOFIPS140: "+strings.TrimSpace(b))
		}
	}
	if !fipsCopyLine.MatchString(src) {
		probs = append(probs, "does not `COPY fipsmode/ ./fipsmode/`, so the startup banner package is missing from the build")
	}
	return probs
}

func TestEveryPublishedImageIsBuiltFIPS(t *testing.T) {
	files := publishedDockerfiles(t, ".")
	// Anti-vacuity: the tree has six service Dockerfiles today. Fewer means the walk is
	// looking in the wrong place, and a pass would mean nothing.
	if len(files) < 6 {
		t.Fatalf("found %d Dockerfiles outside e2e/, want at least 6: %v", len(files), files)
	}
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		if goBuildLine.MatchString(strings.ReplaceAll(string(b), "\r\n", "\n")) {
			checked++
		}
		for _, p := range fipsProblems(string(b)) {
			t.Errorf("%s: %s", filepath.ToSlash(f), p)
		}
	}
	if checked < 6 {
		t.Errorf("only %d Dockerfiles build a Go binary, want at least 6 (firewall, approval, cache, console, scheduler, scanner)", checked)
	}
}

// The check must be able to fail. Each shape a regression takes is caught, and a correct
// Dockerfile passes.
func TestFIPSDockerfileCheckCanFail(t *testing.T) {
	good := "FROM golang AS build\nCOPY fipsmode/ ./fipsmode/\nARG GOFIPS140=v1.0.0\nRUN GOFIPS140=$GOFIPS140 CGO_ENABLED=0 go build -o /x ./x\n"
	if p := fipsProblems(good); p != nil {
		t.Fatalf("a correct Dockerfile was flagged: %v", p)
	}
	bad := map[string]string{
		"no ARG":       strings.Replace(good, "ARG GOFIPS140=v1.0.0\n", "", 1),
		"ARG off":      strings.Replace(good, "GOFIPS140=v1.0.0", "GOFIPS140=off", 1),
		"not passed":   strings.Replace(good, "RUN GOFIPS140=$GOFIPS140 ", "RUN ", 1),
		"no fipsmode":  strings.Replace(good, "COPY fipsmode/ ./fipsmode/\n", "", 1),
		"CRLF, no ARG": strings.ReplaceAll(strings.Replace(good, "ARG GOFIPS140=v1.0.0\n", "", 1), "\n", "\r\n"),
	}
	for name, src := range bad {
		if p := fipsProblems(src); len(p) == 0 {
			t.Errorf("%s: the check passed a broken Dockerfile", name)
		}
	}
	if p := fipsProblems("FROM alpine\nRUN echo no go here\n"); p != nil {
		t.Errorf("a Dockerfile that builds no Go binary was flagged: %v", p)
	}
}
