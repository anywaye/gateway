package api

var _ = struct{}{}

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config oapi-codegen.yaml -generate models,chi-server ../../openapi/v1.yaml
//go:generate go run ./stripbaseurl
