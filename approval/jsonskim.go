package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// jsonSkimmer walks a JSON document from a stream WITHOUT HOLDING IT (#152).
//
// Why this exists instead of encoding/json: the registry documents this service reads
// reach 67 MB (`renovate`'s full packument, measured 2026-09-20) and the chart gives the
// service 128 Mi. json.Decoder.Decode buffers the whole top-level value before it
// unmarshals a byte, and even Decoder.Token buffers one whole string token -- so with the
// standard library, memory is bounded only by the byte budget, and a byte budget big
// enough for a real packument is big enough to OOM the control plane on a hostile one.
//
// What it is, precisely: a STRUCTURAL scanner. It understands just enough JSON to find
// where a value ends -- strings (with escapes), nesting depth, and scalar runs -- and it
// never interprets a value itself. A value the caller wants is CAPTURED as raw bytes, up
// to a bound the caller chooses, and handed to encoding/json to decode; so escapes,
// unicode and numbers are parsed by the standard library, not reimplemented here. A value
// the caller does not want is consumed and forgotten, in constant memory however large.
//
// What it is NOT: a validator. It will walk past malformed content inside a value it is
// skipping (`{"a": tru}` skips fine). That is acceptable for its one job -- harvesting a
// handful of display fields from a registry document -- and would NOT be acceptable on
// an enforcement path, where leniency has to match the real client's. Do not move it
// there.
type jsonSkimmer struct {
	r *bufio.Reader
	// keyBuf is reused for every object key. A 12,000-entry `time` map would otherwise
	// cost 12,000 little capture buffers for strings that are thrown away at once.
	keyBuf []byte
}

func newJSONSkimmer(r io.Reader) *jsonSkimmer {
	return &jsonSkimmer{r: bufio.NewReaderSize(r, 32<<10)}
}

// errSkimCapture means a value the caller asked to KEEP was larger than the bound it
// gave. The value has still been fully consumed, so the walk can continue if the caller
// decides the field is optional.
var errSkimCapture = errors.New("captured value exceeds its bound")

// capture accumulates the raw bytes of one value, up to max.
type capture struct {
	buf  []byte
	max  int
	over bool
}

func (c *capture) add(b byte) {
	if c == nil {
		return
	}
	if len(c.buf) >= c.max {
		c.over = true
		return
	}
	c.buf = append(c.buf, b)
}

// peek skips whitespace and returns the next byte without consuming it.
func (s *jsonSkimmer) peek() (byte, error) {
	for {
		b, err := s.r.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return b, s.r.UnreadByte()
	}
}

// expect consumes the next non-whitespace byte and requires it to be want.
func (s *jsonSkimmer) expect(want byte) error {
	b, err := s.peek()
	if err != nil {
		return err
	}
	if b != want {
		return fmt.Errorf("malformed JSON: expected %q, found %q", want, b)
	}
	_, err = s.r.ReadByte()
	return err
}

// value consumes exactly one JSON value. With a non-nil capture, its raw bytes are kept
// (up to the capture's bound); with nil it is skipped in constant memory.
//
// Nesting is tracked with a COUNTER, not recursion, so a document of a million nested
// arrays costs no stack -- the classic way to kill a recursive-descent parser.
func (s *jsonSkimmer) value(c *capture) error {
	first, err := s.peek()
	if err != nil {
		return err
	}
	switch first {
	case '"':
		return s.str(c)
	case '{', '[':
		depth := 0
		for {
			b, err := s.r.ReadByte()
			if err != nil {
				return unexpectedEOF(err)
			}
			switch b {
			case '"':
				if err := s.r.UnreadByte(); err != nil {
					return err
				}
				if err := s.str(c); err != nil {
					return err
				}
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			c.add(b)
			if depth == 0 {
				return nil
			}
		}
	default:
		// A scalar: number, true, false, null. It ends at the first structural byte or
		// whitespace, which is left unread for the caller.
		for {
			b, err := s.r.ReadByte()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			switch b {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				return s.r.UnreadByte()
			}
			c.add(b)
		}
	}
}

// str consumes one string, including its quotes. The only thing it interprets is the
// backslash, and only to know that the byte after it cannot end the string.
func (s *jsonSkimmer) str(c *capture) error {
	b, err := s.r.ReadByte()
	if err != nil {
		return unexpectedEOF(err)
	}
	if b != '"' {
		return fmt.Errorf("malformed JSON: expected a string, found %q", b)
	}
	c.add(b)
	for {
		b, err := s.r.ReadByte()
		if err != nil {
			return unexpectedEOF(err)
		}
		c.add(b)
		switch b {
		case '\\':
			esc, err := s.r.ReadByte()
			if err != nil {
				return unexpectedEOF(err)
			}
			c.add(esc)
		case '"':
			return nil
		}
	}
}

// object iterates the members of the object at the cursor. For each one, member is
// called with the decoded key, and MUST consume the member's value (by calling value,
// object or array) before it returns.
func (s *jsonSkimmer) object(member func(key string) error) error {
	if err := s.expect('{'); err != nil {
		return err
	}
	for first := true; ; first = false {
		b, err := s.peek()
		if err != nil {
			return unexpectedEOF(err)
		}
		if b == '}' {
			_, err := s.r.ReadByte()
			return err
		}
		if !first {
			if err := s.expect(','); err != nil {
				return err
			}
		}
		key, err := s.key()
		if err != nil {
			return fmt.Errorf("object key: %w", err)
		}
		if err := s.expect(':'); err != nil {
			return err
		}
		if err := member(key); err != nil {
			return err
		}
	}
}

// array iterates the elements of the array at the cursor. element MUST consume one value.
func (s *jsonSkimmer) array(element func() error) error {
	if err := s.expect('['); err != nil {
		return err
	}
	for first := true; ; first = false {
		b, err := s.peek()
		if err != nil {
			return unexpectedEOF(err)
		}
		if b == ']' {
			_, err := s.r.ReadByte()
			return err
		}
		if !first {
			if err := s.expect(','); err != nil {
				return err
			}
		}
		if err := element(); err != nil {
			return err
		}
	}
}

// objectOrSkip is object for a member that SHOULD be an object and might not be. The
// registry types loosely -- a field can be null, or absent, or a string on an old
// document -- and whole-document decoding tolerated `null` into a map. Failing the entire
// harvest because one optional member has the wrong shape would be a regression, so a
// non-object is simply skipped.
func (s *jsonSkimmer) objectOrSkip(member func(key string) error) error {
	b, err := s.peek()
	if err != nil {
		return unexpectedEOF(err)
	}
	if b != '{' {
		return s.value(nil)
	}
	return s.object(member)
}

// arrayOrSkip is the array twin of objectOrSkip.
func (s *jsonSkimmer) arrayOrSkip(element func() error) error {
	b, err := s.peek()
	if err != nil {
		return unexpectedEOF(err)
	}
	if b != '[' {
		return s.value(nil)
	}
	return s.array(element)
}

// key consumes an object key into the reusable scratch buffer and decodes it. A key with
// no backslash is its own decoding (the bytes between the quotes); only an escaped key
// pays for encoding/json.
func (s *jsonSkimmer) key() (string, error) {
	c := capture{buf: s.keyBuf[:0], max: maxSkimKeyBytes}
	err := s.value(&c)
	s.keyBuf = c.buf[:0]
	if err != nil {
		return "", err
	}
	if c.over {
		return "", errSkimCapture
	}
	raw := c.buf
	if len(raw) < 2 || raw[0] != '"' {
		return "", fmt.Errorf("malformed JSON: an object key must be a string")
	}
	for _, b := range raw {
		if b == '\\' {
			var out string
			if err := json.Unmarshal(raw, &out); err != nil {
				return "", err
			}
			return out, nil
		}
	}
	return string(raw[1 : len(raw)-1]), nil
}

// maxSkimKeyBytes bounds an object key. Real keys here are version strings and field
// names; a key this long is not a registry document.
const maxSkimKeyBytes = 1 << 10

// stringValue consumes a value and decodes it as a string, keeping at most max raw bytes.
// A value that is not a string decodes to "" with no error -- the registry's loosely
// typed fields are the caller's problem, and rawValue exists for those.
func (s *jsonSkimmer) stringValue(max int) (string, error) {
	raw, err := s.rawValue(max)
	if err != nil {
		return "", err
	}
	var out string
	if json.Unmarshal(raw, &out) != nil {
		return "", nil
	}
	return out, nil
}

// rawValue consumes a value and returns its raw JSON, or errSkimCapture if it is larger
// than max. Either way the value has been fully consumed.
func (s *jsonSkimmer) rawValue(max int) (json.RawMessage, error) {
	c := &capture{max: max}
	if err := s.value(c); err != nil {
		return nil, err
	}
	if c.over {
		return nil, errSkimCapture
	}
	return c.buf, nil
}

// unexpectedEOF turns a bare EOF in the middle of a value into the error a truncated
// document deserves; a clean EOF between values is the caller's to interpret.
func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
