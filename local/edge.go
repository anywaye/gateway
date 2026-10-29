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
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		},
	}

	log.Printf("edge: https://%s -> %s (Host preserved; routing is the gateway's)", *listen, *backend)
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
