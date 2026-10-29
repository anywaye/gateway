package httpapi

import "os"


// Env reads one environment variable.
//
// An argument rather than a call to `os.Getenv` so that `RuntimeOptions` can be
// driven from a table in a test — and, the reason it matters more here than in
// the TypeScript original, so that the environment is a *parameter* of
// configuration rather than a thing any package in this module can reach.
//
// `src/index.ts` (removed at cutover) types its parameter `Record<string, string | undefined>` and
// defaults it to `Bun.env`. The difference is the point: a default value that
// reads the real environment is a function that can read the real environment,
// so there is no default here and `cmd/gateway` names what it is doing instead.
type Env func(key string) string

// OSEnv is the production reader: the process's own environment.
//
// It is named rather than inlined at the call site so that `cmd/gateway` reads as
// handing its environment to the configuration reader, instead of calling
// `os.Getenv` itself and making the boundary invisible.
func OSEnv(key string) string { return os.Getenv(key) }

func trimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && isASCIISpace(value[start]) {
		start++
	}
	for end > start && isASCIISpace(value[end-1]) {
		end--
	}
	return value[start:end]
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}
