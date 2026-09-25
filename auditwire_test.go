package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The gate and the control plane are separate binaries with separate AuditEvent types
// that share a wire format and no constant. A field added on the gate's side that the
// control plane's type does not name is not an error anywhere: encoding/json drops it
// on decode and the record simply never has it.
//
// That happened. D182 (#20) added deny_kind, rule and source to the gate's audit event
// with a comment saying an exported decision log is now "attributable without log
// correlation". The approval service's AuditEvent had no such fields, so every event
// arrived, was stored without them, and the export never carried them -- true of the
// wire, false of the record, for as long as nobody compared the two types. #142 needed
// the source of a block and found the field empty on every row.
//
// This test compares the two types by their JSON keys: every key the gate EMITS must be
// a key the control plane STORES. The gate's keys come from the real struct via
// reflection; the control plane's come from parsing its source, because the two are
// different `package main`s and cannot import each other.
func TestEveryAuditFieldTheGateEmitsIsStoredByTheControlPlane(t *testing.T) {
	emitted := jsonKeys(reflect.TypeOf(auditEvent{}))
	if len(emitted) < 8 {
		t.Fatalf("read only %d json keys off the gate's auditEvent; the reflection is broken", len(emitted))
	}
	stored := approvalStructKeys(t, "AuditEvent", 8)
	if missing := keysNotStored(emitted, stored); len(missing) > 0 {
		t.Errorf("the gate emits audit fields the control plane does not store: %v. Each one is silently "+
			"dropped on ingest, so the record and the export never carry it. Add the field to approval/store.go's "+
			"AuditEvent (and its column, insert and scan in pgstore.go), or stop emitting it.", missing)
	}
}

// approvalStructKeys reads one struct's JSON keys out of approval/store.go by parsing the
// source. atLeast guards the parse: a type renamed or moved must fail loudly rather than
// let the comparison pass against an empty set.
func approvalStructKeys(t *testing.T, typeName string, atLeast int) map[string]bool {
	t.Helper()
	stored := map[string]bool{}
	f, err := parser.ParseFile(token.NewFileSet(), "approval/store.go", nil, 0)
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
	if len(stored) < atLeast {
		t.Fatalf("read only %d json keys off approval/store.go's %s; the parse is broken", len(stored), typeName)
	}
	return stored
}

func keysNotStored(emitted []string, stored map[string]bool) []string {
	var missing []string
	for _, k := range emitted {
		if !stored[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing
}

func jsonKeys(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		key := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if key != "" && key != "-" {
			out = append(out, key)
		}
	}
	return out
}

// TestTheAuditWireGuardCanFail: with the gate's Rule field renamed on the wire, the guard
// must name it. Done by a copy of the struct rather than by editing the real one.
func TestTheAuditWireGuardCanFail(t *testing.T) {
	type drifted struct {
		Package string `json:"package"`
		Rule    string `json:"rule_id"` // renamed: the control plane stores "rule"
	}
	missing := keysNotStored(jsonKeys(reflect.TypeOf(drifted{})), map[string]bool{"package": true, "rule": true})
	if len(missing) != 1 || missing[0] != "rule_id" {
		t.Fatalf("the comparison did not flag the drifted key: %v", missing)
	}
}
