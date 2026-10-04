module github.com/cafaye/gateway

// The SAME number `pantry/go.mod` and `identity/go.mod` already state, and the
// gate asserts all three copies against each other — see `bin/prime-go`. Nothing
// makes the go command read `mise.toml`, so a toolchain pin that lives only
// there is a comment.
go 1.26.1

require (
	github.com/go-chi/chi/v5 v5.3.2
	github.com/oapi-codegen/runtime v1.7.0
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
)
