package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Provisioned from the backend CLI through a trusted channel; included in the binary.
// This is a public key, never a private key or a root downloaded at runtime.
//
//go:embed keys/root-public.pem
var rootPublicKeyPEM []byte

func embeddedRootPublicKey() (ed25519.PublicKey, error) {
	block, rest := pem.Decode(rootPublicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("la raíz integrada debe contener una única clave pública PEM")
	}
	return decodePublicKey(block.Bytes)
}

// An explicitly provisioned public key is a local trust anchor, not a manifest cache.
func localIssuerKey(path string, id byte) (map[byte]issuerKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("se requiere un archivo PEM PUBLIC KEY")
	}
	if _, err := decodePublicKey(block.Bytes); err != nil {
		return nil, err
	}
	return map[byte]issuerKey{id: {KeyID: int(id), PublicKey: block.Bytes, Status: "ACTIVE"}}, nil
}

type signedManifest struct {
	Manifest  []byte `json:"manifest"`
	Signature []byte `json:"signature"`
}

type issuerKey struct {
	KeyID     int    `json:"key_id"`
	PublicKey []byte `json:"public_key"`
	Status    string `json:"status"`
}

type keyManifest struct {
	Version int         `json:"version"`
	Keys    []issuerKey `json:"keys"`
}

func decodePublicKey(der []byte) (ed25519.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("clave pública X.509 inválida: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("la clave pública no es Ed25519")
	}
	return key, nil
}

func trustedKeys(envelope signedManifest, root ed25519.PublicKey) (map[byte]issuerKey, error) {
	if len(root) != ed25519.PublicKeySize || !ed25519.Verify(root, envelope.Manifest, envelope.Signature) {
		return nil, fmt.Errorf("la firma raíz del manifiesto no es válida")
	}
	var manifest keyManifest
	if err := json.Unmarshal(envelope.Manifest, &manifest); err != nil {
		return nil, fmt.Errorf("manifiesto inválido: %w", err)
	}
	if manifest.Version != 1 {
		return nil, fmt.Errorf("versión de manifiesto no soportada: %d", manifest.Version)
	}
	keys := make(map[byte]issuerKey)
	for _, key := range manifest.Keys {
		if key.KeyID < 0 || key.KeyID > 255 {
			return nil, fmt.Errorf("keyId fuera de rango")
		}
		id := byte(key.KeyID)
		if _, exists := keys[id]; exists {
			return nil, fmt.Errorf("keyId duplicado: %d", id)
		}
		if key.Status != "ACTIVE" && key.Status != "REVOKED" && key.Status != "EXPIRED" {
			return nil, fmt.Errorf("estado de clave desconocido: %s", key.Status)
		}
		if _, err := decodePublicKey(key.PublicKey); err != nil {
			return nil, err
		}
		keys[id] = key
	}
	return keys, nil
}

func fetchKeys(endpoint string) (map[byte]issuerKey, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	return fetchKeysWithClient(endpoint, client)
}

func fetchKeysWithClient(endpoint string, client *http.Client) (map[byte]issuerKey, error) {
	envelope, err := downloadManifest(endpoint, client)
	if err != nil {
		return nil, err
	}
	root, err := embeddedRootPublicKey()
	if err != nil {
		return nil, err
	}
	return trustedKeys(envelope, root)
}

func downloadManifest(endpoint string, client *http.Client) (signedManifest, error) {
	var envelope signedManifest
	response, err := client.Get(endpoint)
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return envelope, fmt.Errorf("el servidor de claves %s no respondió dentro del tiempo de espera; no se ha verificado la firma: %w", endpoint, err)
		}
		return envelope, fmt.Errorf("descargar claves: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return envelope, fmt.Errorf("servidor de claves: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return envelope, err
	}
	if len(body) > 1024*1024 {
		return envelope, fmt.Errorf("manifiesto demasiado grande")
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return envelope, fmt.Errorf("respuesta de claves inválida: %w", err)
	}
	return envelope, nil
}

func verifyCredential(credential *Credential, keys map[byte]issuerKey) error {
	if credential.Version != 1 {
		return fmt.Errorf("versión de credencial no soportada: %d", credential.Version)
	}
	key, ok := keys[credential.KeyID]
	if !ok {
		return fmt.Errorf("clave emisora desconocida: %d", credential.KeyID)
	}
	if key.Status != "ACTIVE" {
		return fmt.Errorf("clave emisora %d: %s", credential.KeyID, key.Status)
	}
	publicKey, err := decodePublicKey(key.PublicKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, credential.Payload, credential.Signature) {
		return fmt.Errorf("firma de credencial inválida")
	}
	return nil
}
