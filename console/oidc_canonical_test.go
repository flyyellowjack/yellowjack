package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const b64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// respellings returns every string that differs from seg ONLY in its last character and
// that a LENIENT base64url decoder reads as the same bytes. Unpadded base64 leaves 2 or 4
// unused bits in the final character of most lengths, and Go's default decoder ignores
// them -- so a value has several spellings, all carrying the identical MAC.
func respellings(t *testing.T, seg string) []string {
	t.Helper()
	want, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("the genuine segment does not decode: %v", err)
	}
	var out []string
	for i := 0; i < len(b64urlAlphabet); i++ {
		alt := seg[:len(seg)-1] + string(b64urlAlphabet[i])
		if alt == seg {
			continue
		}
		if got, err := base64.RawURLEncoding.DecodeString(alt); err == nil && bytes.Equal(got, want) {
			out = append(out, alt)
		}
	}
	return out
}

// A session cookie has exactly ONE accepted spelling.
//
// Found from the outside in: e2e leg 27 tampered the last character of the cookie and the
// console accepted it about 1 run in 16. The console was not wrong about the MAC -- the
// "tampered" value decoded to the same bytes -- but it was accepting strings it had never
// issued. That is not a forgery and not a bypass; it IS malleability in a security token,
// and it made a correct-looking tamper test vacuous a fixed fraction of the time. Strict
// decoding removes the slack, so the question "is this the cookie we minted?" has one
// answer per cookie.
func TestSessionCookieHasExactlyOneSpelling(t *testing.T) {
	f := newFakeIdP(t)
	o := newTestOIDC(t, f)
	good := signIn(t, o, f, "/")

	accepted := func(v string) bool {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: v})
		return o.check(req) != ""
	}
	if !accepted(good.Value) {
		t.Fatal("control: the genuine cookie was refused, so nothing below is evidence")
	}

	dot := strings.LastIndexByte(good.Value, '.')
	payload, mac := good.Value[:dot], good.Value[dot+1:]

	// ANTI-VACUITY. A 32-byte MAC is 43 characters, which always leaves 2 unused bits:
	// three respellings must exist. If none do, this test is iterating over nothing.
	macAlts := respellings(t, mac)
	if len(macAlts) != 3 {
		t.Fatalf("expected exactly 3 lenient respellings of a 43-character MAC, found %d -- the MAC length or "+
			"encoding changed and this test no longer exercises what it claims", len(macAlts))
	}
	for _, alt := range macAlts {
		if accepted(payload + "." + alt) {
			t.Errorf("accepted a cookie the console never issued: MAC respelled %q -> %q (same bytes, different text)", mac, alt)
		}
	}
	// The payload half has slack only at some lengths; when it does, the same rule holds.
	for _, alt := range respellings(t, payload) {
		if accepted(alt + "." + mac) {
			t.Errorf("accepted a cookie the console never issued: payload respelled (same bytes, different text)")
		}
	}
}
