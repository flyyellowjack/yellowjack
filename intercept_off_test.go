//go:build !intercept

package main

import (
	"errors"
	"net/http/httptest"
	"testing"
)

// A build without interception must REFUSE a configuration that asks for it. Starting
// anyway would leave an operator believing clients are enforced when they can route
// around the gate -- a posture worse than a failed start.
func TestDefaultBuildRefusesAnInterceptionConfig(t *testing.T) {
	ic, err := setupInterception(Config{InterceptListen: ":8443", InterceptCAFile: "/ca.pem"}, nil)
	if !errors.Is(err, errNoInterception) || ic != nil {
		t.Fatalf("interception configured on a build without it: got (%v, %v), want a refusal", ic, err)
	}

	// CONTROL: the ordinary configuration starts, with no interception listener.
	ic, err = setupInterception(Config{}, nil)
	if err != nil || ic != nil {
		t.Fatalf("an ordinary configuration was refused or given a listener: (%v, %v)", ic, err)
	}

	// And nothing in this build treats a request as intercepted.
	if intercepted(httptest.NewRequest("GET", "http://gate/x", nil)) {
		t.Fatal("a request is reported as intercepted in a build without the mode")
	}
}
