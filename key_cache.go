package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const keyCacheMaxAge = time.Hour

type keySyncOptions struct {
	Endpoint  string
	CachePath string
	Offline   bool
	Refresh   bool
}

type cachedManifest struct {
	Version  int            `json:"version"`
	Endpoint string         `json:"endpoint"`
	SavedAt  time.Time      `json:"savedAt"`
	Envelope signedManifest `json:"envelope"`
}

func defaultKeysCachePath() (string, error) {
	directory, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "BiblioDesk", "nfc-agent", "keys-manifest.json"), nil
}

func loadCachedKeys(options keySyncOptions, root ed25519.PublicKey) (map[byte]issuerKey, error) {
	file, err := os.Open(options.CachePath)
	if err != nil {
		return nil, fmt.Errorf("abrir caché: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 2*1024*1024 {
		return nil, fmt.Errorf("caché demasiado grande")
	}
	var cached cachedManifest
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("caché inválida: %w", err)
	}
	if cached.Version != 1 || cached.Endpoint != options.Endpoint {
		return nil, fmt.Errorf("la caché no corresponde a este servidor")
	}
	age := time.Since(cached.SavedAt)
	if age < 0 || age > keyCacheMaxAge {
		return nil, fmt.Errorf("la caché expiró o tiene una fecha inválida; sincroniza las claves")
	}
	// Never trust the parsed keys on disk without rechecking the root signature.
	return trustedKeys(cached.Envelope, root)
}

func saveCachedManifest(options keySyncOptions, envelope signedManifest) error {
	data, err := json.MarshalIndent(cachedManifest{Version: 1, Endpoint: options.Endpoint, SavedAt: time.Now().UTC(), Envelope: envelope}, "", "    ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(options.CachePath)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".keys-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, options.CachePath)
}

func syncIssuerKeys(options keySyncOptions) (map[byte]issuerKey, string, error) {
	root, err := embeddedRootPublicKey()
	if err != nil {
		return nil, "", err
	}
	return syncIssuerKeysWithRoot(options, root, &http.Client{Timeout: 10 * time.Second})
}

func syncIssuerKeysWithRoot(options keySyncOptions, root ed25519.PublicKey, client *http.Client) (map[byte]issuerKey, string, error) {
	if options.CachePath == "" {
		return nil, "", fmt.Errorf("falta la ruta de caché")
	}
	if options.Offline || !options.Refresh {
		keys, err := loadCachedKeys(options, root)
		if err == nil {
			return keys, "caché", nil
		}
		if options.Offline {
			return nil, "", err
		}
	}
	envelope, err := downloadManifest(options.Endpoint, client)
	if err != nil {
		return nil, "", err
	}
	keys, err := trustedKeys(envelope, root)
	if err != nil {
		return nil, "", err
	}
	if err := saveCachedManifest(options, envelope); err != nil {
		return nil, "", fmt.Errorf("claves verificadas, pero no se pudo guardar la caché: %w", err)
	}
	return keys, "servidor", nil
}
