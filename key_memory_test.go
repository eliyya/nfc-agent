package main

import (
    "crypto/ed25519"
    "encoding/json"
    "os"
    "testing"
    "time"
)

func TestMemoryKeysReuseExpiryAndRefresh(t *testing.T) {
    options, root, private, envelope, server := cacheFixture(t)
    options.memory = &issuerMemoryCache{}
    if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil { t.Fatal(err) }
    options.Refresh = false
    options.Offline = true
    if err := os.Remove(options.CachePath); err != nil { t.Fatal(err) }
    if _, source, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil || source != "memoria" {
        t.Fatalf("memory reuse failed without disk: %s %v", source, err)
    }
    options.memory.savedAt = time.Now().Add(-2*time.Hour)
    if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err == nil { t.Fatal("expired memory accepted") }
    options.Offline = false
    options.Refresh = true
    if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil { t.Fatal(err) }
    var manifest keyManifest
    if err := json.Unmarshal(envelope.Manifest, &manifest); err != nil { t.Fatal(err) }
    manifest.Keys[0].Status = "REVOKED"
    data, err := json.Marshal(manifest)
    if err != nil { t.Fatal(err) }
    envelope.Manifest = data
    envelope.Signature = ed25519.Sign(private, data)
    if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil { t.Fatal(err) }
    options.Refresh = false
    keys, source, err := syncIssuerKeysWithRoot(options, root, server.Client())
    if err != nil || source != "memoria" || keys[1].Status != "REVOKED" { t.Fatalf("revocation not applied: %s %v", source, err) }
}

func TestMemoryPreservesDiskExpiry(t *testing.T) {
    options, root, _, _, server := cacheFixture(t)
    if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil { t.Fatal(err) }
    data, err := os.ReadFile(options.CachePath)
    if err != nil { t.Fatal(err) }
    var cached cachedManifest
    if err := json.Unmarshal(data, &cached); err != nil { t.Fatal(err) }
    cached.SavedAt = time.Now().Add(-59*time.Minute)
    data, err = json.Marshal(cached)
    if err != nil { t.Fatal(err) }
    if err := os.WriteFile(options.CachePath, data, 0600); err != nil { t.Fatal(err) }
    options.Refresh = false
    options.memory = &issuerMemoryCache{}
    if _, _, err := syncIssuerKeysWithRoot(options, root, server.Client()); err != nil { t.Fatal(err) }
    if !options.memory.savedAt.Equal(cached.SavedAt) { t.Fatal("disk lifetime extended") }
}
