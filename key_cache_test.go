package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func cacheFixture(t *testing.T) (keySyncOptions, ed25519.PublicKey, ed25519.PrivateKey, *signedManifest, *httptest.Server) {
	t.Helper()
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(issuer)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(keyManifest{Version: 1, Keys: []issuerKey{{KeyID: 1, PublicKey: der, Status: "ACTIVE"}}})
	if err != nil {
		t.Fatal(err)
	}
	envelope := &signedManifest{Manifest: manifest, Signature: ed25519.Sign(private, manifest)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(envelope); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	options := keySyncOptions{Endpoint: server.URL, CachePath: filepath.Join(t.TempDir(), "keys.json"), Refresh: true}
	return options, root, private, envelope, server
}

func TestKeyCacheDownloadAndOffline(t *testing.T) {
	options, root, _, _, server := cacheFixture(t)
	keys, source, err := syncIssuerKeysWithRoot(options, root, server.Client())
	if err != nil || source != "servidor" || len(keys) != 1 {
		t.Fatalf("descarga fallida: %s %v", source, err)
	}
	server.Close()
	options.Offline = true
	cached, source, err := syncIssuerKeysWithRoot(options, root, server.Client())
	if err != nil || source != "caché" || len(cached) != 1 {
		t.Fatalf("lectura offline fallida: %s %v", source, err)
	}
	options.Offline = false
	options.Refresh = false
	if _, source, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil || source != "caché" {
		t.Fatalf("no se reutilizó la caché: %v", err)
	}
}

func TestKeyCacheRejectsAlterationExpiryAndOtherServer(t *testing.T) {
	options, root, _, _, server := cacheFixture(t)
	if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(options.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		alter func(*cachedManifest)
	}{
		{"alteración", func(c *cachedManifest) { c.Envelope.Manifest = append(c.Envelope.Manifest, ' ') }},
		{"expirada", func(c *cachedManifest) { c.SavedAt = time.Now().Add(-2 * keyCacheMaxAge) }},
		{"futura", func(c *cachedManifest) { c.SavedAt = time.Now().Add(time.Hour) }},
		{"otro servidor", func(c *cachedManifest) { c.Endpoint = "https://other.example/keys" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cached cachedManifest
			if err := json.Unmarshal(original, &cached); err != nil {
				t.Fatal(err)
			}
			test.alter(&cached)
			data, err := json.Marshal(cached)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(options.CachePath, data, 0600); err != nil {
				t.Fatal(err)
			}
			offline := options
			offline.Offline = true
			if _, _, err := syncIssuerKeysWithRoot(offline, root, server.Client()); err == nil {
				t.Fatal("se aceptó una caché inválida")
			}
		})
	}
}

func TestInvalidDownloadDoesNotOverwriteCache(t *testing.T) {
	options, root, _, envelope, server := cacheFixture(t)
	if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(options.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature[0] ^= 1
	if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err == nil {
		t.Fatal("se aceptó la descarga alterada")
	}
	after, err := os.ReadFile(options.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("una descarga inválida reemplazó la caché")
	}
}

func TestRefreshPersistsRevocation(t *testing.T) {
	options, root, private, envelope, server := cacheFixture(t)
	if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil {
		t.Fatal(err)
	}
	var manifest keyManifest
	if err := json.Unmarshal(envelope.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Keys[0].Status = "REVOKED"
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Manifest = data
	envelope.Signature = ed25519.Sign(private, data)
	if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil {
		t.Fatal(err)
	}
	options.Offline = true
	keys, _, err := syncIssuerKeysWithRoot(options, root, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if keys[1].Status != "REVOKED" {
		t.Fatal("se perdió el estado de revocación al leer la caché")
	}
}
