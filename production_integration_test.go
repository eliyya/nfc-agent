//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// This opt-in test issues an ephemeral synthetic credential, without writing a card.
func TestProductionTrustChain(t *testing.T) {
	keys, err := fetchKeys("https://nfc.eliyya.dev/keys")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Post("https://nfc.eliyya.dev/credentials", "application/json", bytes.NewBufferString(`{"userId":"00123456"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatal(fmt.Sprintf("emisión HTTP %d", response.StatusCode))
	}
	var body struct {
		Credential []byte `json:"credential"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	// Use the same MIME NDEF record shape that Android writes to a card.
	if len(body.Credential) != 70 {
		t.Fatalf("longitud de credencial: %d", len(body.Credential))
	}
	message := append([]byte{0xd2, byte(len(credentialMIME)), 70}, []byte(credentialMIME)...)
	message = append(message, body.Credential...)
	credential, err := parseCredential(message)
	if err != nil {
		t.Fatal(err)
	}
	if credential.UserID != "00123456" {
		t.Fatal("userId inesperado")
	}
	if err := verifyCredential(credential, keys); err != nil {
		t.Fatal(err)
	}
}
