package httpapi

import "os"

// The environment reader, and the only code in this module that touches one.
//
// It is its own file because that is the whole claim, and a claim about which
// lines of which file are allowed to read the process's environment is not
// checkable while the reader shares a file with the thing it feeds.
// `TestExactlyOneFileInThisPackageTouchesTheProcessEnvironment` reads this
// directory and fails if any other file calls `os.Getenv`, or if this one grows
// a second call site.
//
// Go makes this easier to lose than TypeScript did. There, the environment was
// `Bun.env` and reaching for it was a deliberate act with a name. Here
// `os.Getenv` is a free function any package may call at any time, so the
// property `guard/AGENTS.md` asks for — *"Configuration arrives as an argument,
// never as a module-level global read from the environment"* — is not
// maintained by avoiding a global. It is maintained by there being exactly one
// function here, and by everything downstream of it taking an `Env` it is
// handed.

// Env reads one environment variable.
//
// An argument rather than a call to `os.Getenv` so that `RuntimeOptions` can be
// driven from a table in a test — and, the reason it matters more here than in
// the TypeScript original, so that the environment is a *parameter* of
// configuration rather than a thing any package in this module can reach.
//
// `src/index.ts` types its parameter `Record<string, string | undefined>` and
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

// trimSpace trims the ASCII whitespace a compose file leaves behind, which is
// what `src/index.ts`'s `?.trim()` does. Not `strings.TrimSpace`, because that
// trims Unicode whitespace the shell never produced and would make `PORT` and
// `PORT` with a non-breaking space agree.
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
