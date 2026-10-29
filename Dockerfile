ARG GO_VERSION=1.26

FROM golang:${GO_VERSION} AS source
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

FROM redis:7-bookworm AS redis-tool

FROM source AS test
COPY --from=redis-tool /usr/local/bin/redis-server /usr/local/bin/redis-server
RUN redis-server --version && go vet ./... && go test -count=1 -v ./...

FROM source AS build
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/service ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/service /app/service
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/service"]