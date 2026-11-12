package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRejectManifestSignedByUntrustedRoot(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"version":1,"keys":[]}`)
	envelope := signedManifest{Manifest: manifest, Signature: ed25519.Sign(private, manifest)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(envelope); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	keys, err := fetchKeysWithClient(server.URL, server.Client())
	if err == nil || !strings.Contains(err.Error(), "firma raíz") || keys != nil {
		t.Fatalf("se aceptó un manifiesto firmado por una raíz ajena: %v", err)
	}
}

func TestKeyServerTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	keys, err := fetchKeysWithClient(server.URL, &http.Client{Timeout: 50 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "no se ha verificado la firma") {
		t.Fatalf("se esperaba un error de verificación pendiente, recibido: %v", err)
	}
	if keys != nil {
		t.Fatal("no deben devolverse claves cuando el servidor no responde")
	}
}

func TestKeyServerErrors(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			keys, err := fetchKeysWithClient(server.URL, server.Client())
			if err == nil || !strings.Contains(err.Error(), "HTTP") || keys != nil {
				t.Fatalf("se aceptó respuesta HTTP inválida: %v", err)
			}
		})
	}
}
