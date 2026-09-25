package main

import (
	"encoding/json"
	"strings"
)

// decodeJSON is a tiny helper so the adversarial tests assert on PARSEABILITY the way a
// real client does, rather than on substring shapes.
func decodeJSON(s string, v any) error {
	return json.NewDecoder(strings.NewReader(s)).Decode(v)
}
