// Command edge is the local loop's TLS terminator — and ONLY the local loop's.
//
// It listens on 127.0.0.1:19443 with the locally generated certificate from
// `local/run.sh keygen` and forwards every byte to the gateway over plain HTTP,
// preserving `Host`. Host-based routing is the gateway's job (`VHOST_TABLE`);
// this process terminates TLS and does nothing else, because a second place that
// decides where a request goes is a second place to get the api/auth split wrong.
//
// It is stdlib-only (`crypto/tls` + `httputil.ReverseProxy`) so the loop adds no
// dependency to the module, and it is never deployed: no Dockerfile copies it,
// no manifest names it, and `run.sh` builds it by path (`go build ./local`) so
// `go build ./...` in the gate never has to decide what it is.
//
// Usage: edge -listen 127.0.0.1:19443 -backend http://127.0.0.1:19090 -cert local/cert.pem -key local/key.pem
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:19443", "TLS listen address")
	backend := flag.String("backend", "http://127.0.0.1:19090", "gateway base URL over plain HTTP")
	cert := flag.String("cert", "local/cert.pem", "server certificate PEM")
	key := flag.String("key", "local/key.pem", "server key PEM")
	flag.Parse()

	target, err := url.Parse(*backend)
	if err != nil {
		log.Fatalf("edge: backend is not a URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	server := &http.Server{
		Addr:    *listen,
		Handler: proxy,
		TLSConfig: &tls.Config{
			// The loop's clients pin the local CA (`--cacert`, `SSL_CERT_FILE`);
			// the server side needs no client certificates and asks for none.
			MinVersion: tls.VersionTLS12,
			// http/1.1 ONLY. Go's ReverseProxy forwards an HTTP/2 request body
			// unreliably to an http/1.1 backend (the BFF read an empty body and
			// answered 'must be a JSON object'), and nothing in the loop needs
			// multiplexing — one edge, five backends, curl and one browser.
			NextProtos: []string{"http/1.1"},
		},
	}

	log.Printf("edge: https://%s -> %s (Host preserved; routing is the gateway's)", *listen, *backend)
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
