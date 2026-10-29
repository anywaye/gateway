package ratelimit

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// EncodeCommand writes one RESP2 command: `*<n>\r\n$<len>\r\n<arg>\r\n...`.
//
// Pure, and tested without a socket, because getting a byte count wrong is the
// classic way a hand-rolled client corrupts a command in a way that reads as a
// server fault rather than a client fault.
func EncodeCommand(args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("ratelimit: encodeCommand: a command needs at least a name")
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&buf, "$%d\r\n", len(arg))
		buf.WriteString(arg)
		buf.WriteString("\r\n")
	}
	return buf.Bytes(), nil
}

// Value is a decoded RESP2 value: a simple string, an integer, a bulk string, an
// array, or nil.
//
// Go's `any` rather than a sum type, because every consumer in this package asks
// "is this the shape I expected" and a sum type would make that a type switch at
// each of the three call sites instead of one assertion in `VerdictOf`.
type Value any

// ReplyError is a complete error reply, carrying the bytes it used.
//
// It is an `error`, so `parseReply`'s contract is unchanged for a caller that
// only wants to know it failed, and it carries `Read` for the socket reader, which
// does need the difference.
type ReplyError struct {
	Message string

	Read int
}

func (e *ReplyError) Error() string { return e.Message }

// ParseReply reads one RESP2 value from `buf` at `at`, and how many bytes it used.
//
// An error reply THROWS. `-ERR` from `EVAL` means the script did not run, and
// treating that as "no quota used" is a limiter that is open exactly when the
// thing it depends on is broken.
func ParseReply(buf []byte, at int) (value Value, read int, err error) {
	if at >= len(buf) {
		return nil, 0, errors.New("ratelimit: redis sent a truncated reply")
	}

	marker := buf[at]
	line, after, err := readLine(buf, at)
	if err != nil {
		return nil, 0, err
	}

	switch marker {
	case '+':
		return line, after - at, nil

	case '-':
		return nil, 0, &ReplyError{Message: "ratelimit: redis said " + line, Read: after - at}

	case ':':
		value, err := integer(line)
		if err != nil {
			return nil, 0, err
		}
		return value, after - at, nil

	case '$':
		length, err := integer(line)
		if err != nil {
			return nil, 0, err
		}
		if length < 0 {
			return nil, after - at, nil
		}

		start := after
		if start+length+2 > len(buf) {
			return nil, 0, errors.New("ratelimit: redis sent a truncated reply")
		}
		return string(buf[start : start+length]), after - at + length + 2, nil

	case '*':
		length, err := integer(line)
		if err != nil {
			return nil, 0, err
		}
		if length < 0 {
			return nil, after - at, nil
		}

		items := make([]Value, 0, length)
		cursor := after
		for i := 0; i < length; i++ {
			item, used, err := ParseReply(buf, cursor)
			if err != nil {
				return nil, 0, err
			}
			items = append(items, item)
			cursor += used
		}
		return items, cursor - at, nil

	default:
		return nil, 0, fmt.Errorf("ratelimit: redis sent an unknown reply type %q", string(marker))
	}
}

func readLine(buf []byte, at int) (line string, after int, err error) {
	for i := at + 1; i < len(buf)-1; i++ {
		if buf[i] == '\r' && buf[i+1] == '\n' {
			return string(buf[at+1 : i]), i + 2, nil
		}
	}
	return "", 0, errors.New("ratelimit: redis sent a truncated reply")
}

func integer(line string) (int, error) {
	value, err := strconv.Atoi(line)
	if err != nil {
		return 0, fmt.Errorf("ratelimit: redis sent %q where a whole number was due", line)
	}
	return value, nil
}
