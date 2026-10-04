package api

// The generation wiring, and the two questions a reader has about a generated
// tree answered here rather than in a document nobody is required to read.
//
// # The pin
//
// oapi-codegen v2.8.0, pinned to an exact version on the line below rather than
// in oapi-codegen.yaml. `go run <module>@<version>` resolves in module-aware
// mode and ignores this module's go.mod, so the generator is a build tool
// invoked on purpose and cannot be moved by `go get`.
//
// # The document is this repository's own
//
// `openapi/v1.yaml` is the contract the TypeScript implementation already serves
// and the one this rewrite stays compatible with. There is no vendored copy and
// no provenance file: the generated code and the document sit in the same
// commit, so the only way they can disagree is a regeneration that was not
// committed — which `bin/prime-go` makes a gate rather than a runtime surprise.
//
// The consequence is stated rather than hidden: **regeneration is only correct
// immediately after the document changes, in the same commit.**
//
// # WHAT IS EDITED IN THE GENERATED FILE, AND WHY IT IS NOT A DRIFT
//
// `bin/prime-go` regenerates and diffs, so a hand edit in `api.gen.go` is a
// permanently red gate. There is exactly one edit, and it is the SECOND
// `//go:generate` line above: `internal/api/stripbaseurl` removes the
// `options.BaseURL+` token from the route registrations, because core's
// account-scope checker cannot read a route whose path is an expression, and a
// gateway whose whole surface reads as `route_defs=0` is a gateway nobody is
// measuring. Read that command's own header before touching `api.gen.go`.
var _ = struct{}{}

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config oapi-codegen.yaml -generate models,chi-server ../../openapi/v1.yaml
//go:generate go run ./stripbaseurl
