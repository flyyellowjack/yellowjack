package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Streaming harvest of an npm packument (#152).
//
// The developer lookup needs four things from a document that can be 67 MB: the latest
// version, when it was published, how many versions and maintainers there are, and
// whether the latest is deprecated. Decoding the whole document to get them is what made
// ten of twenty popular packages unreadable under this service's 8 MB cap (#139), and
// raising that cap is not available -- the process has 128 Mi.
//
// So the document is WALKED, and only those four things are kept.
//
// # The common case costs O(1) memory, and the uncommon one is bounded
//
// Measured on three live packuments (lodash, typescript, renovate): the top-level order
// is `_id, _rev, name, dist-tags, versions, time, ...` every time. With `dist-tags`
// first, `latest` is known before either map is met, so exactly one entry is retained
// from each -- the version count is a counter, not a map.
//
// That order is an OBSERVATION about one registry, not a contract; mirrors and other
// registry implementations owe us nothing. When `versions` or `time` arrives before
// `dist-tags`, candidates are retained until `latest` is known, under two bounds that
// turn an unbounded map into an error: a count of entries and a total of retained bytes.
//
// # Two budgets, because bytes alone do not bound memory
//
// npmPackumentMaxBytes bounds what we will READ: time and bandwidth from a registry that
// never stops sending. It can be generous precisely because reading no longer costs
// memory. The retention bounds below are what protect the heap, and they are separate
// because a hostile document of distinct tiny keys grows a map far faster than it grows
// the byte count.
const (
	// 4x the largest real packument measured (renovate, 66.9 MB, 2026-09-20).
	npmPackumentMaxBytes = 256 << 20
	// Bounds every COUNT in the document. Counting costs no memory, so this is about not
	// reading forever. Real maximum observed: 5,556 versions (renovate). ~47x headroom.
	npmMaxCountedEntries = 1 << 18
	// Bounds what is HELD in the out-of-order fallback. Measured, not guessed: a retained
	// entry costs roughly 150 bytes of heap once the map's own overhead is counted, not
	// the ~30 its key and value suggest, so 262,144 entries was ~40 MB of a 128 Mi
	// process. Real maximum observed: 12,057 `time` entries (renovate). ~5x headroom.
	npmMaxRetainedEntries = 1 << 16
	// What may be HELD while `latest` is still unknown. renovate's entire `time` map is
	// ~0.6 MB of keys and values.
	npmMaxRetainedBytes = 8 << 20
	// One kept value: a timestamp, or a deprecation message a maintainer typed.
	npmMaxKeptValueBytes = 64 << 10
)

// harvestNpmPackument reads a packument from r and returns the lookup's projection of it.
func harvestNpmPackument(r io.Reader) (upstreamHarvest, error) {
	lr := &io.LimitedReader{R: r, N: npmPackumentMaxBytes}
	h, err := walkNpmPackument(newJSONSkimmer(lr))
	if err != nil {
		// Same rule as decodeCapped: if the budget is spent, the failure is the budget,
		// whatever shape the truncated document made it take.
		if lr.N <= 0 {
			return upstreamHarvest{}, fmt.Errorf("%w (cap %s)", errBodyTooLarge, capText(npmPackumentMaxBytes))
		}
		return upstreamHarvest{}, err
	}
	return h, nil
}

func walkNpmPackument(s *jsonSkimmer) (upstreamHarvest, error) {
	var (
		h        upstreamHarvest
		latest   string
		retained int // bytes held in the two maps below
		// Populated only for entries that might be `latest`: all of them until it is
		// known, exactly one afterwards.
		times      = map[string]string{}
		deprecated = map[string]json.RawMessage{}
	)
	hold := func(n int) error {
		retained += n
		if retained > npmMaxRetainedBytes || len(times)+len(deprecated) > npmMaxRetainedEntries {
			return fmt.Errorf("%w: more version data than this service will hold before "+
				"`dist-tags` names the latest version", errBodyTooLarge)
		}
		return nil
	}
	wanted := func(version string) bool { return latest == "" || version == latest }

	err := s.object(func(key string) error {
		switch key {
		case "dist-tags":
			return s.objectOrSkip(func(tag string) error {
				if tag != "latest" {
					return s.value(nil)
				}
				v, err := s.stringValue(maxSkimKeyBytes)
				latest = v
				return err
			})

		case "versions":
			return s.objectOrSkip(func(version string) error {
				// Counting costs no memory, so without its own bound a registry could keep
				// us reading `"x":{},` until the byte budget -- 23 million entries. No real
				// package is within two orders of magnitude of this.
				if h.VersionCount++; h.VersionCount > npmMaxCountedEntries {
					return fmt.Errorf("%w: more than %d versions", errBodyTooLarge, npmMaxCountedEntries)
				}
				if !wanted(version) {
					return s.value(nil) // the common case: skipped whole, in constant memory
				}
				return s.objectOrSkip(func(field string) error {
					if field != "deprecated" {
						return s.value(nil)
					}
					raw, err := s.rawValue(npmMaxKeptValueBytes)
					if errors.Is(err, errSkimCapture) {
						// An absurdly long deprecation message is still a deprecation.
						raw, err = json.RawMessage(`true`), nil
					}
					if err != nil {
						return err
					}
					deprecated[version] = raw
					return hold(len(version) + len(raw))
				})
			})

		case "time":
			return s.objectOrSkip(func(version string) error {
				if !wanted(version) {
					return s.value(nil)
				}
				ts, err := s.stringValue(npmMaxKeptValueBytes)
				if err != nil && !errors.Is(err, errSkimCapture) {
					return err
				}
				times[version] = ts
				return hold(len(version) + len(ts))
			})

		case "maintainers":
			return s.arrayOrSkip(func() error {
				if h.Maintainers++; h.Maintainers > npmMaxCountedEntries {
					return fmt.Errorf("%w: more than %d maintainers", errBodyTooLarge, npmMaxCountedEntries)
				}
				return s.value(nil)
			})
		}
		return s.value(nil)
	})
	if err != nil {
		return upstreamHarvest{}, err
	}

	h.LatestVersion = latest
	if latest != "" {
		if t, err := time.Parse(time.RFC3339, times[latest]); err == nil {
			h.PublishedAt = t
		}
		h.Deprecated = normalizeDeprecated(deprecated[latest])
	}
	return h, nil
}
