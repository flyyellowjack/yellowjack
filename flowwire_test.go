package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// The capacity telemetry is the THIRD wire format the gate and the control plane share
// without a shared type, after the audit event (auditwire_test.go) and the L2 score
// record (scorewire_test.go). Those two got a guard when a field went missing across
// them. This one had none, and the silence is identical: the gate marshals
// flowBucketDTO, the control plane unmarshals approval.FlowBucket, and encoding/json
// DISCARDS a key the receiver does not name -- no error, no warning, a counter that
// reads zero forever while the sender faithfully increments it.
//
// Written while adding integrity_mismatches (#64), but deliberately general: it guards
// every field on this payload, including the ones that were already there.

func flowApprovalKeys(t *testing.T, typeName string, atLeast int) map[string]bool {
	t.Helper()
	stored := map[string]bool{}
	f, err := parser.ParseFile(token.NewFileSet(), "approval/flowstore.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != typeName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil {
				continue
			}
			tag := reflect.StructTag(strings.Trim(fld.Tag.Value, "`")).Get("json")
			if key := strings.Split(tag, ",")[0]; key != "" && key != "-" {
				stored[key] = true
			}
		}
		return false
	})
	// The floor is what stops a renamed or moved type turning this into a comparison
	// against an empty set, which passes while checking nothing.
	if len(stored) < atLeast {
		t.Fatalf("read only %d json keys off approval/flowstore.go's %s; the parse is broken", len(stored), typeName)
	}
	return stored
}

func TestEveryFlowFieldTheGateSendsIsStoredByTheControlPlane(t *testing.T) {
	emitted := jsonKeys(reflect.TypeOf(flowBucketDTO{}))
	if len(emitted) < 8 {
		t.Fatalf("read only %d json keys off the gate's flowBucketDTO; the reflection is broken", len(emitted))
	}
	if missing := keysNotStored(emitted, flowApprovalKeys(t, "FlowBucket", 8)); len(missing) > 0 {
		t.Errorf("the gate sends capacity fields the control plane does not store: %v. Each one is "+
			"silently dropped by encoding/json on ingest, so the counter reads zero on the console "+
			"forever. Add the field to approval/flowstore.go's FlowBucket (and its column in "+
			"flowpgstore.go), or stop sending it.", missing)
	}
}

// The console reads the SUMMARY, which is a different struct again, so the chain has a
// second link with the same failure mode: a field stored by the control plane but not
// named by the console's own type is stored and then invisible.
func TestEveryFlowSummaryFieldIsNamedByTheConsole(t *testing.T) {
	stored := flowApprovalKeys(t, "FlowSummary", 8)
	// Parsed the same way rather than reflected, because console is a separate package
	// this test cannot import -- which is the whole reason the seam exists.
	consoleKeys := map[string]bool{}
	f, err := parser.ParseFile(token.NewFileSet(), "console/flowclient.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "flowSummary" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil {
				continue
			}
			tag := reflect.StructTag(strings.Trim(fld.Tag.Value, "`")).Get("json")
			if key := strings.Split(tag, ",")[0]; key != "" && key != "-" {
				consoleKeys[key] = true
			}
		}
		return false
	})
	if len(consoleKeys) < 8 {
		t.Fatalf("read only %d json keys off console/flowclient.go's flowSummary; the parse is broken", len(consoleKeys))
	}
	var missing []string
	for k := range stored {
		if !consoleKeys[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("the control plane stores capacity fields the console never names: %v — stored, "+
			"served, and invisible to the only person who reads them.", missing)
	}
}

// TestTheFlowWireGuardCanFail is the negative control. A guard over a seam is worth
// exactly what its ability to fail is worth, and this family's failure mode is passing
// vacuously -- see the floors above.
func TestTheFlowWireGuardCanFail(t *testing.T) {
	stored := flowApprovalKeys(t, "FlowBucket", 8)
	emitted := append(jsonKeys(reflect.TypeOf(flowBucketDTO{})), "a_key_nobody_stores")
	if missing := keysNotStored(emitted, stored); len(missing) != 1 || missing[0] != "a_key_nobody_stores" {
		t.Errorf("the guard did not report an unstored key: %v — it cannot catch the defect it exists for", missing)
	}
}

// TestTheIntegrityCounterSurvivesTheWire decodes LITERAL wire bytes rather than
// round-tripping a struct through itself.
//
// The distinction is the point and it is why the key-diff guards above are not enough
// on their own: a round-trip through one type is structurally blind to a key mismatch,
// because the same field names are used to write and to read. These are the bytes a
// gate actually sends.
func TestTheIntegrityCounterSurvivesTheWire(t *testing.T) {
	const onTheWire = `{
		"bucket_start":"2026-09-22T00:00:00Z","ecosystem":"oci","package":"library/x","kind":"artifact",
		"requests":5,"bytes_upstream":100,"bytes_client":100,
		"truncated":1,"relay_errors":0,"transport_errors":0,"upstream_status":0,"meta_errors":0,"retries":2,
		"integrity_mismatches":3
	}`
	var got flowBucketDTO
	if err := json.Unmarshal([]byte(onTheWire), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.IntegrityMismatches != 3 {
		t.Errorf("integrity_mismatches decoded as %d, want 3 — the json tag does not match what is sent",
			got.IntegrityMismatches)
	}
	// The sibling counters are asserted too, so a tag rename anywhere on this payload
	// fails here rather than in whichever dashboard someone reads six weeks later.
	if got.Truncated != 1 || got.Retries != 2 || got.Requests != 5 {
		t.Errorf("a neighbouring counter decoded wrong: %+v", got)
	}
}
