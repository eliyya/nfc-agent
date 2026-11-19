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
    "sync"
)

const keyCacheMaxAge = time.Hour

type keySyncOptions struct {
    Endpoint  string
    CachePath string
    Offline   bool
    Refresh   bool
    memory *issuerMemoryCache
}

// Keys are immutable after publication. The lock serializes refresh and reads.
type issuerMemoryCache struct {
    mu sync.Mutex
    keys map[byte]issuerKey
    endpoint string
    path string
    root string
    savedAt time.Time
}

var processIssuerKeys issuerMemoryCache

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

func loadCachedKeys(options keySyncOptions, root ed25519.PublicKey) (map[byte]issuerKey, time.Time, error) {
    file, err := os.Open(options.CachePath)
    if err != nil {
        return nil, time.Time{}, fmt.Errorf("abrir caché: %w", err)
    }
    defer file.Close()
    data, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
    if err != nil {
        return nil, time.Time{}, err
    }
    if len(data) > 2*1024*1024 {
        return nil, time.Time{}, fmt.Errorf("caché demasiado grande")
    }
    var cached cachedManifest
    if err := json.Unmarshal(data, &cached); err != nil {
        return nil, time.Time{}, fmt.Errorf("caché inválida: %w", err)
    }
    if cached.Version != 1 || cached.Endpoint != options.Endpoint {
        return nil, time.Time{}, fmt.Errorf("la caché no corresponde a este servidor")
    }
    age := time.Since(cached.SavedAt)
    if age < 0 || age > keyCacheMaxAge {
        return nil, time.Time{}, fmt.Errorf("la caché expiró o tiene una fecha inválida; sincroniza las claves")
    }
    // Never trust the parsed keys on disk without rechecking the root signature.
    keys, err := trustedKeys(cached.Envelope, root)
    return keys, cached.SavedAt, err
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
    options.memory = &processIssuerKeys
    return syncIssuerKeysWithRoot(options, root, &http.Client{Timeout: 10 * time.Second})
}

func syncIssuerKeysWithRoot(options keySyncOptions, root ed25519.PublicKey, client *http.Client) (map[byte]issuerKey, string, error) {
    if options.memory != nil {
        memory := options.memory
        memory.mu.Lock()
        defer memory.mu.Unlock()
        age := time.Since(memory.savedAt)
        if !options.Refresh && memory.keys != nil && memory.endpoint == options.Endpoint &&
            memory.path == options.CachePath && memory.root == string(root) &&
            age >= 0 && age <= keyCacheMaxAge {
            return memory.keys, "memoria", nil
        }
        // Never fall back to old in-memory keys after a failed explicit refresh.
        memory.keys = nil
    }

    if options.CachePath == "" {
        return nil, "", fmt.Errorf("falta la ruta de caché")
    }
    if options.Offline || !options.Refresh {
        keys, savedAt, err := loadCachedKeys(options, root)
        if err == nil {
            rememberIssuerKeys(options, root, keys, savedAt)
            return keys, "caché", nil
        }
        if options.Offline {
            return nil, "", err
        }
    }
    savedAt := time.Now()
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
    rememberIssuerKeys(options, root, keys, savedAt)
    return keys, "servidor", nil
}


func rememberIssuerKeys(options keySyncOptions, root ed25519.PublicKey, keys map[byte]issuerKey, savedAt time.Time) {
    if memory := options.memory; memory != nil {
        memory.keys = keys
        memory.endpoint = options.Endpoint
        memory.path = options.CachePath
        memory.root = string(root)
        memory.savedAt = savedAt
    }
}
