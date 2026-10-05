// RESP2, hand-rolled.
//
// `src/middleware/rateLimitRedis.ts` (removed at cutover) writes its own encoder and parser and gives
// the reason: "this is forty lines of RESP2, and the client half of it is covered
// by the pure `encodeCommand`/`parseReply` tests". The reason it is worth repeating
// here is that a general-purpose Redis client would be a dependency this repository
// does not have — and, more to the point, the whole of this package's distributed
// half is ONE script and ONE ping. Every command a client library would add is a
// command whose reply shape has to be reasoned about, and this limiter only ever
// asks two questions of Redis.
//
// # `ReplyError` IS THE POINT OF THIS FILE
//
// `-ERR` is a REPLY, not a broken stream: Redis sends one deliberately, keeps the
// connection in sync, and answers the next command normally. So the socket reader
// has to be able to tell "this reply said no" — which fails ONE command — from
// "these bytes are half a reply" — which means wait for more.
//
// A bare `error` carries no such distinction, and a reader that treats both the
// same re-parses the same `-ERR` on every subsequent chunk and wedges the
// connection for the life of the process. `rateLimitRedis.ts` records that this was
// a real defect, found by running against a real server: "one `-ERR` reply used to
// wedge this connection permanently". `ReplyError` carries the byte count so the
// reader can consume exactly the reply it failed on and carry on.
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

	// How many bytes this reply occupied. The reader consumes exactly this many
	// and keeps going; that is the whole difference from a broken stream.
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
	case '+': // simple string
		return line, after - at, nil

	case '-': // error
		return nil, 0, &ReplyError{Message: "ratelimit: redis said " + line, Read: after - at}

	case ':': // integer
		value, err := integer(line)
		if err != nil {
			return nil, 0, err
		}
		return value, after - at, nil

	case '$': // bulk string
		length, err := integer(line)
		if err != nil {
			return nil, 0, err
		}
		if length < 0 {
			// `$-1` is the null bulk string.
			return nil, after - at, nil
		}

		start := after
		if start+length+2 > len(buf) {
			return nil, 0, errors.New("ratelimit: redis sent a truncated reply")
		}
		return string(buf[start : start+length]), after - at + length + 2, nil

	case '*': // array
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

// readLine is the text after the marker, up to and including the CRLF, and the
// offset just past it.
//
// The loop bound is `len(buf)-1` rather than `len(buf)`, because a CRLF needs two
// bytes and the reference's `readLine` has the same bound — a reply whose CRLF is
// split across two reads is "wait for more", which is the case the whole design
// turns on.
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
