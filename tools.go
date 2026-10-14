//go:build tools

// The build tool this repository runs, declared as a dependency rather than
// fetched on demand.
//
// `bin/prime-go` regenerates `internal/api/api.gen.go` by running oapi-codegen
// through `go generate ./internal/api/`. Spelled as `go run <module>@<version>`
// that invocation resolves in a throwaway module context: Go fetches the
// tool's whole transitive graph into the module cache at run time, and on a
// machine whose cache has never seen it — every fresh CI runner — the
// regeneration cannot run at all. A generator that cannot run is not a gate
// that passed.
//
// So the generator is a blank import here instead. `go mod tidy` records it
// and its graph in `go.mod`/`go.sum`, `go mod download` (which CI runs, and
// which `setup-go`'s cache is keyed on) populates the whole graph, and the
// `//go:generate` line runs the tool out of this module rather than out of a
// throwaway one. The `tools` tag keeps it out of `go build ./...` and
// `go vet ./...`: it is never linked into the binary, it only pins the graph.
//
// The version is read, never written: it was taken from the `//go:generate`
// pin by the `go get` that added it, and `go.mod` is now the one copy.
package tools

import (
	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
)
