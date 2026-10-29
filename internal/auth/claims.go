package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Claims is a JSON object with its members in the order the document wrote them.
//
// The zero value is an empty object, which marshals as `{}` — so a payload that
// decoded to nothing still produces valid JSON rather than a nil pointer.
type Claims struct {
	members []claimMember
	index   map[string]int
}

type claimMember struct {
	name  string
	value any
}

func newClaims(members []claimMember) Claims {
	c := Claims{members: members, index: make(map[string]int, len(members))}
	for i, member := range members {
		c.index[member.name] = i
	}
	return c
}

// UnmarshalJSON reads a payload, keeping member order.
//
// `json.Decoder.Token` rather than `json.Unmarshal` into a map, and that is the
// whole mechanism: `Unmarshal` has already thrown the order away by the time it
// hands back a `map[string]json.RawMessage`, and no amount of sorting afterwards
// recovers it. `Token` walks the document as the reader saw it.
func (c *Claims) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))

	value, err := decodeOrdered(dec)
	if err != nil {
		return err
	}

	members, ok := value.([]claimMember)
	if !ok {
		return fmt.Errorf("auth: a JWT claims set must be a top-level JSON object")
	}

	*c = newClaims(members)
	return nil
}

// MarshalJSON writes the members back in the order they were read.
func (c Claims) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, member := range c.members {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, err := json.Marshal(member.name)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(member.value)
		if err != nil {
			return nil, err
		}
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// String is a claim's value when it is a non-empty string, and "" otherwise.
//
// One accessor rather than four, because the three questions every caller in
// this package asks about a claim are the same three: is it a string, is it
// empty, and what is it. `principalOf` needs that for `sub`, for `scope` and for
// `account_id`, and `accountIdOf` in `internal/ratelimit` needs it again — the
// same shape of question asked from a different package is still one answer.
func (c Claims) String(name string) string {
	at, ok := c.index[name]
	if !ok {
		return ""
	}
	text, ok := c.members[at].value.(string)
	if !ok {
		return ""
	}
	return text
}

// Lookup is a claim's raw decoded value and whether the claim was present at
// all.
//
// Presence and type are separate questions and the difference matters in exactly
// one place: `principalOf` REJECTS a `scope` claim that is present and is not a
// string, while it IGNORES an `account_id` that is present and is not a string.
// A single accessor that conflated them would make one of those two behaviors
// unreachable.
func (c Claims) Lookup(name string) (any, bool) {
	at, ok := c.index[name]
	if !ok {
		return nil, false
	}
	return c.members[at].value, true
}

// Len is how many members the object has. Used by the tests that prove a
// duplicated key kept one position rather than two.
func (c Claims) Len() int { return len(c.members) }

// ClaimsFrom builds a `Claims` from a map, in **sorted key order**.
//
// # WHY IT EXISTS, AND WHY IT IS NOT A SECOND WAY TO PARSE A TOKEN
//
// A caller that never had a token has no order to preserve — it holds a Go map,
// and `encoding/json` renders that map sorted. So sorted is not a loss here; it is
// the only order such a caller could have produced anyway. What this must not be
// mistaken for is `UnmarshalJSON`, which keeps the order a token wrote and is what
// every real principal is built by. A principal that did not come from a token has
// no token order, and saying so in the signature is better than a comment.
//
// The duplicate-key rule cannot bite — a Go map cannot hold one key twice — and
// the slice and the index are built together by the one constructor, so a `Claims`
// from here cannot be in the state where `Lookup` answers "absent" for every name
// in it. That is the failure `newClaims` exists to make unreachable.
func ClaimsFrom(members map[string]any) Claims {
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)

	ordered := make([]claimMember, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, claimMember{name: name, value: members[name]})
	}
	return newClaims(ordered)
}

func decodeOrdered(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}

	switch delim {
	case '{':
		return decodeOrderedObject(dec)
	case '[':
		return decodeOrderedArray(dec)
	default:
		return nil, fmt.Errorf("auth: unexpected %q where a JSON value was due", delim)
	}
}

func decodeOrderedObject(dec *json.Decoder) ([]claimMember, error) {
	members := []claimMember{}
	at := map[string]int{}

	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("auth: a JSON object key was not a string")
		}

		value, err := decodeOrdered(dec)
		if err != nil {
			return nil, err
		}

		if seen, dup := at[name]; dup {
			members[seen].value = value
			continue
		}
		at[name] = len(members)
		members = append(members, claimMember{name: name, value: value})
	}

	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return members, nil
}

func decodeOrderedArray(dec *json.Decoder) ([]any, error) {
	items := []any{}

	for dec.More() {
		item, err := decodeOrdered(dec)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return items, nil
}
