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

// The console's `event` is the THIRD copy of the audit event's shape (gate -> approval
// -> console), and the same silence applies at this seam as at the first: a key the
// approval service sends that this struct does not name is dropped by encoding/json with
// no error, and the page simply never shows it. auditwire_test.go (root package) holds
// the gate's keys inside the approval service's; this holds the approval service's keys
// inside the console's, so a field can no longer be stored and then not displayed.
//
// Direction matters: the console may name FEWER keys than the approval service only by
// listing them here as deliberate omissions, with the reason.
var eventKeysTheConsoleDeliberatelyIgnores = map[string]string{}

func TestEveryStoredAuditFieldReachesTheConsole(t *testing.T) {
	stored := approvalStructJSONKeys(t, "AuditEvent", 10)
	shown := jsonKeySet(reflect.TypeOf(event{}))
	var missing []string
	for _, k := range stored {
		if !shown[k] {
			if _, deliberate := eventKeysTheConsoleDeliberatelyIgnores[k]; !deliberate {
				missing = append(missing, k)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the approval service stores audit fields the console's `event` does not name: %v. They are dropped "+
			"on decode and can never reach a page. Add them to `event` (and render or deliberately not render them), "+
			"or list them in eventKeysTheConsoleDeliberatelyIgnores with the reason.", missing)
	}
	for k := range eventKeysTheConsoleDeliberatelyIgnores {
		if shown[k] {
			t.Errorf("%q is listed as deliberately ignored but the console names it; remove the stale entry", k)
		}
	}
}

// approvalStructJSONKeys reads the JSON keys of one struct type out of the approval
// service's store.go by parsing the source, because the two are separate `package main`s
// that cannot import each other. atLeast guards the parse: a pattern that stops matching
// must fail loudly rather than pass by comparing against nothing.
func approvalStructJSONKeys(t *testing.T, typeName string, atLeast int) []string {
	t.Helper()
	src, err := parser.ParseFile(token.NewFileSet(), "../approval/store.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	ast.Inspect(src, func(n ast.Node) bool {
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
			key := strings.Split(reflect.StructTag(strings.Trim(fld.Tag.Value, "`")).Get("json"), ",")[0]
			if key != "" && key != "-" {
				keys = append(keys, key)
			}
		}
		return false
	})
	if len(keys) < atLeast {
		t.Fatalf("read only %d keys off approval/store.go's %s; the parse is broken", len(keys), typeName)
	}
	return keys
}

func jsonKeySet(rt reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		if key := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]; key != "" && key != "-" {
			out[key] = true
		}
	}
	return out
}
