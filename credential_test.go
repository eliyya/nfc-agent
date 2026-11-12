package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func sampleMessage() []byte {
	payload := make([]byte, 70)
	payload[0] = 1
	payload[1] = 1
	binary.BigEndian.PutUint32(payload[2:6], 1234567)
	message := []byte{0xd2, byte(len(credentialMIME)), 70}
	message = append(message, credentialMIME...)
	return append(message, payload...)
}

func TestAndroidFormat(t *testing.T) {
	message := sampleMessage()
	tlv := append([]byte{0, 3, byte(len(message))}, message...)
	tlv = append(tlv, 0xfe)
	ndef, err := ndefFromTLV(tlv)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := parseCredential(ndef)
	if err != nil {
		t.Fatal(err)
	}
	if credential.UserID != "01234567" || credential.Version != 1 || credential.KeyID != 1 || len(credential.Signature) != 64 {
		t.Fatalf("credencial inesperada: %+v", credential)
	}
	for i := 0; i < len(message); i++ {
		if _, err := parseCredential(message[:i]); err == nil {
			t.Fatalf("se aceptó mensaje truncado a %d bytes", i)
		}
	}
	for i := 0; i < len(tlv)-1; i++ {
		if _, err := ndefFromTLV(tlv[:i]); err == nil {
			t.Fatalf("se aceptó TLV truncado a %d bytes", i)
		}
	}
}

func TestRejectMalformedNDEF(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { b[0] |= 0x20; return b },
		func(b []byte) []byte { b[0] &^= 0x80; return b },
		func(b []byte) []byte { b[0] &^= 0x40; return b },
		func(b []byte) []byte { b[3] = 'x'; return b },
		func(b []byte) []byte { return append(b, 0) },
	} {
		if _, err := parseCredential(mutate(sampleMessage())); err == nil {
			t.Fatal("se aceptó NDEF inválido")
		}
	}
}

func TestTrustChain(t *testing.T) {
	root, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuer, issuerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKIXPublicKey(issuer)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(keyManifest{Version: 1, Keys: []issuerKey{{KeyID: 1, PublicKey: der, Status: "ACTIVE"}}})
	envelope := signedManifest{Manifest: manifest, Signature: ed25519.Sign(rootPrivate, manifest)}
	keys, err := trustedKeys(envelope, root)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := parseCredential(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	credential.Signature = ed25519.Sign(issuerPrivate, credential.Payload)
	if err := verifyCredential(credential, keys); err != nil {
		t.Fatal(err)
	}
	credential.Payload[5] ^= 1
	if err := verifyCredential(credential, keys); err == nil {
		t.Fatal("se aceptó credencial alterada")
	}
	credential.Payload[5] ^= 1
	key := keys[1]
	key.Status = "REVOKED"
	keys[1] = key
	if err := verifyCredential(credential, keys); err == nil {
		t.Fatal("se aceptó clave revocada")
	}
	delete(keys, 1)
	if err := verifyCredential(credential, keys); err == nil {
		t.Fatal("se aceptó clave desconocida")
	}
	envelope.Manifest[0] ^= 1
	if _, err := trustedKeys(envelope, root); err == nil {
		t.Fatal("se aceptó manifiesto alterado")
	}
}
