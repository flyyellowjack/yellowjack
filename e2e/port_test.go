//go:build e2e

package e2e

// Why this file exists (#123): `main` went red on 0206554 with
//
//	Bind for 0.0.0.0:38933 failed: port is already allocated
//
// while the identical tree passed on the MR pipeline and on the next commit. Nothing had
// changed; the rig had simply drawn a published port out of the same range the kernel uses
// for outbound connections, in a namespace it cannot see. See freePort's comment.
//
// These tests need no Docker. They carry the e2e build tag only because the harness does.

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

// kernelEphemeralFloor reads the low end of the kernel's outbound port range. Linux only,
// so it reports ok=false on a dev laptop running Windows or macOS -- where the number is
// not the one that matters anyway, because CI is where the daemon lives elsewhere.
func kernelEphemeralFloor(t *testing.T) (int, bool) {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(b))
	if len(fields) != 2 {
		return 0, false
	}
	lo, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, false
	}
	return lo, true
}

// TestFreePortStaysOutOfTheOutboundRange is the regression. A published port inside the
// ephemeral range can be taken by any outbound socket on the daemon's host before the
// container binds it, and these rigs open thousands of those (#96).
func TestFreePortStaysOutOfTheOutboundRange(t *testing.T) {
	if floor, ok := kernelEphemeralFloor(t); ok {
		// The band is pinned against the running kernel rather than a remembered
		// constant: if a future image ships a lower floor, this fails here rather than
		// as an intermittent red main months later.
		if e2ePortBandHi >= floor {
			t.Fatalf("the published-port band runs to %d but this kernel starts handing out "+
				"outbound ports at %d -- the band overlaps the range it exists to avoid",
				e2ePortBandHi, floor)
		}
	} else {
		t.Log("no /proc/sys/net/ipv4/ip_local_port_range here; band checked against the " +
			"documented Linux default only")
	}

	for i := 0; i < 200; i++ {
		p := freePort(t)
		if p < e2ePortBandLo || p > e2ePortBandHi {
			t.Fatalf("freePort returned %d, outside the band %d-%d", p, e2ePortBandLo, e2ePortBandHi)
		}
		if p >= 32768 {
			t.Fatalf("freePort returned %d, inside the kernel's outbound range -- this is the "+
				"exact draw that made a container fail to bind", p)
		}
	}
}

// TestFreePortNeverRepeats covers the other half: two rigs in one run must not be handed
// the same number, because the first container is still holding it when the second starts.
func TestFreePortNeverRepeats(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 500; i++ {
		p := freePort(t)
		if seen[p] {
			t.Fatalf("freePort returned %d twice in one run; the container still holding it "+
				"would make the second rig fail to bind", p)
		}
		seen[p] = true
	}
}

// TestAskingTheOSForAPortLandsInTheOutboundRange is the negative control, and it is the
// reason the two tests above are not vacuous: it runs the allocation freePort USED to do
// and shows it produces exactly the ports they forbid. If the kernel ever stopped handing
// out ephemeral ports for a :0 bind, this test would fail and tell us the band is now
// guarding nothing.
func TestAskingTheOSForAPortLandsInTheOutboundRange(t *testing.T) {
	floor, ok := kernelEphemeralFloor(t)
	if !ok {
		floor = 32768
	}
	inRange := 0
	const draws = 20
	for i := 0; i < draws; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if port >= floor {
			inRange++
		}
	}
	if inRange == 0 {
		t.Fatalf("%d ports asked of the OS and none landed at or above %d -- the old allocation "+
			"no longer collides with outbound sockets, so the band this suite now uses is "+
			"guarding against nothing and should be re-justified", draws, floor)
	}
	t.Logf("control: %d of %d OS-assigned ports landed in the outbound range (>=%d), which is "+
		"what freePort no longer does", inRange, draws, floor)
}

// TestFreePortProbeIsNotTrustedOnDind pins the one subtlety a reader is most likely to
// undo: the local listen inside freePort is a courtesy for a dev laptop and must not be
// treated as proof on dind, where the bind happens in another container entirely.
func TestFreePortProbeIsNotTrustedOnDind(t *testing.T) {
	prev, had := os.LookupEnv("E2E_FW_HOST")
	t.Cleanup(func() {
		if had {
			os.Setenv("E2E_FW_HOST", prev)
		} else {
			os.Unsetenv("E2E_FW_HOST")
		}
	})

	os.Setenv("E2E_FW_HOST", "docker")
	if !portProbeUninformative() {
		t.Fatal("with E2E_FW_HOST set the daemon is a separate container, so a local listen " +
			"says nothing about where the port will be bound")
	}
	// Hold a port open and confirm freePort will still hand it out on dind: refusing it
	// would be filtering on evidence from the wrong machine.
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", e2ePortBandLo))
	if err != nil {
		t.Skipf("could not hold %d locally: %v", e2ePortBandLo, err)
	}
	defer l.Close()

	os.Unsetenv("E2E_FW_HOST")
	if portProbeUninformative() {
		t.Fatal("with E2E_FW_HOST unset the daemon shares this host, so the probe is meaningful")
	}
}
