package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	certFile := flag.String("cert", "/tmp/oauth2-cert.pem", "Path to certificate file")
	keyFile := flag.String("key", "/tmp/oauth2-key.pem", "Path to key file")
	port := flag.Int("port", 443, "Port to listen on")
	flag.Parse()

	// Create an HTTP handler that:
	// 1. Returns a dummy OAuth2 token for POST /token requests
	// 2. Proxies all other requests to the storage-testbench emulator (localhost:9000)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && r.Method == http.MethodPost {
			// Handle OAuth2 token requests
			w.Header().Set("Content-Type", "application/json")
			response := map[string]interface{}{
				"access_token": "dummy-token-for-emulator",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			json.NewEncoder(w).Encode(response)
		} else {
			// Proxy all other requests to the storage-testbench emulator
			// The emulator runs on HTTP (port 9000), not HTTPS
			emulatorURL := "http://localhost:9000" + r.URL.Path
			if r.URL.RawQuery != "" {
				emulatorURL += "?" + r.URL.RawQuery
			}

			// Create a new request to the emulator
			proxyReq, err := http.NewRequest(r.Method, emulatorURL, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Copy headers from the original request
			for key, values := range r.Header {
				for _, value := range values {
					proxyReq.Header.Add(key, value)
				}
			}

			// Make the request to the emulator
			client := &http.Client{}
			resp, err := client.Do(proxyReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			// Copy response headers
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			// Copy status code and body
			w.WriteHeader(resp.StatusCode)
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				// Response already started, can't send error
				return
			}
		}
	})

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create server
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", *port),
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down mock OAuth2 server...")
		server.Close()
		os.Exit(0)
	}()

	log.Printf("Mock OAuth2 server listening on port %d", *port)
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
