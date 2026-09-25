// mavenrepo is a one-artifact Maven repository for the strict-checksum e2e leg (#147).
//
// The claim under test is "an artifact and the checksums beside it survive the gate, as
// judged by the real client". Real Maven Central cannot host the negative control: the
// control needs an upstream whose checksum does NOT match its artifact, so that `mvn -C`
// is shown able to fail. This fixture serves one artifact honestly, or -- by
// MAVENREPO_TAMPER -- with exactly one thing wrong:
//
//	(unset)   the artifact, its POM, and correct .sha1/.md5 sidecars for both
//	sidecar   the .jar.sha1 is a well-formed hash OF DIFFERENT BYTES
//	artifact  one byte of the .jar is flipped; the sidecars still describe the original
//
// In both tampered modes everything is still well-formed (40 hex characters, same
// length jar), so nothing fails on parsing: the ONLY thing wrong is that the checksum no
// longer authenticates the bytes. That is the substitution a checksum exists to catch.
//
// It RECORDS every path it serves at /_seen, because a green `mvn` proves nothing if mvn
// never came through the gate to this repository at all.
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	base = "/org/example/yjfixture/goodlib/2.1.0/goodlib-2.1.0"
	pom  = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example.yjfixture</groupId>
  <artifactId>goodlib</artifactId>
  <version>2.1.0</version>
  <packaging>jar</packaging>
  <scm><url>https://github.com/example/goodlib</url></scm>
</project>
`
)

// jarBytes is not a real archive and does not need to be: dependency:get downloads and
// checksums an artifact without opening it. It is binary on purpose (NUL, 0xFF, CRLF),
// so a relay that treated it as text would change its hash.
func jarBytes() []byte {
	b := []byte{'P', 'K', 0x03, 0x04, 0x00, 0xFF, 0xFE, '\r', '\n', '\r', ' ', '\n'}
	for i := 0; i < 2048; i++ {
		b = append(b, byte(i*31+7))
	}
	return b
}

func sha1hex(b []byte) string { s := sha1.Sum(b); return hex.EncodeToString(s[:]) }
func md5hex(b []byte) string  { s := md5.Sum(b); return hex.EncodeToString(s[:]) }

func main() {
	tamper := os.Getenv("MAVENREPO_TAMPER")
	jar := jarBytes()

	files := map[string][]byte{
		base + ".jar":      jar,
		base + ".jar.sha1": []byte(sha1hex(jar)),
		base + ".jar.md5":  []byte(md5hex(jar)),
		base + ".pom":      []byte(pom),
		base + ".pom.sha1": []byte(sha1hex([]byte(pom))),
		base + ".pom.md5":  []byte(md5hex([]byte(pom))),
	}
	switch tamper {
	case "":
	case "sidecar":
		files[base+".jar.sha1"] = []byte(sha1hex([]byte("different bytes entirely")))
		// Maven falls back to the next algorithm when one is missing, not when one
		// MISMATCHES -- but remove the fallback anyway so the leg cannot pass through it.
		delete(files, base+".jar.md5")
	case "artifact":
		forged := append([]byte(nil), jar...)
		forged[len(forged)/2] ^= 0x01
		files[base+".jar"] = forged
	default:
		log.Fatalf("mavenrepo: unknown MAVENREPO_TAMPER %q (want unset, sidecar or artifact)", tamper)
	}

	var mu sync.Mutex
	var seen []string

	http.HandleFunc("/_seen", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tamper": tamper, "seen": seen})
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/_") {
			mu.Lock()
			seen = append(seen, r.URL.Path)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	})

	addr := os.Getenv("MAVENREPO_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("mavenrepo: serving %s.* on %s (tamper=%q)", base, addr, tamper)
	log.Fatal(http.ListenAndServe(addr, nil))
}
