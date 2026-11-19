package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "encoding/json"
    "testing"
)

func v2Bytes(kind byte, identifier string) []byte {
    data := append([]byte{2, 1, kind, byte(len(identifier))}, []byte(identifier)...)
    return append(data, make([]byte, 64)...)
}

func ndefCredential(data []byte) []byte {
    message := append([]byte{0xd2, byte(len(credentialMIME)), byte(len(data))}, credentialMIME...)
    return append(message, data...)
}

func TestV2Credentials(t *testing.T) {
    public, private, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    der, err := x509.MarshalPKIXPublicKey(public)
    if err != nil {
        t.Fatal(err)
    }
    keys := map[byte]issuerKey{1: {KeyID: 1, PublicKey: der, Status: "ACTIVE"}}
    for _, tc := range []struct {
        kind            byte
        typ, identifier string
    }{
        {1, "student", "00123456"},
        {2, "teacher", "GODE561231GR8"},
        {2, "teacher", "ÑOÑE561231GR8"},
        {2, "teacher", "&ODE561231GR8"},
        {3, "book", "ISC-001-0044-01"},
    } {
        t.Run(tc.identifier, func(t *testing.T) {
            data := v2Bytes(tc.kind, tc.identifier)
            signedLength := len(data) - 64
            copy(data[signedLength:], ed25519.Sign(private, data[:signedLength]))
            message := ndefCredential(data)
            credential, err := parseCredential(message)
            if err != nil {
                t.Fatal(err)
            }
            if credential.Type != tc.typ || credential.Identifier != tc.identifier || credential.Version != 2 {
                t.Fatalf("unexpected credential: %+v", credential)
            }
            if (tc.kind == 1 && credential.UserID != tc.identifier) || (tc.kind != 1 && credential.UserID != "") {
                t.Fatal("incorrect legacy userId")
            }
            if err := verifyCredential(credential, keys); err != nil {
                t.Fatal(err)
            }
            // Every signed header/identifier byte and signature byte is authenticated.
            for i := range data {
                altered := append([]byte(nil), data...)
                altered[i] ^= 1
                parsed, err := parseCredential(ndefCredential(altered))
                if err == nil && verifyCredential(parsed, keys) == nil {
                    t.Fatalf("accepted mutation at %d", i)
                }
            }
            for i := 0; i < len(message); i++ {
                if _, err := parseCredential(message[:i]); err == nil {
                    t.Fatalf("accepted truncation %d", i)
                }
            }
            key := keys[1]
            for _, status := range []string{"REVOKED", "EXPIRED"} {
                key.Status = status
                if verifyCredential(credential, map[byte]issuerKey{1: key}) == nil {
                    t.Fatal("accepted inactive key")
                }
            }
            if verifyCredential(credential, nil) == nil {
                t.Fatal("accepted unknown key")
            }
        })
    }
}

func TestInvalidV2(t *testing.T) {
    cases := [][]byte{
        {}, {2}, {2, 1}, {2, 1, 1},
        v2Bytes(0, "00123456"), v2Bytes(4, "00123456"),
        v2Bytes(1, ""), v2Bytes(1, "1234567"), v2Bytes(1, "123456789"),
        v2Bytes(1, "0012345A"), v2Bytes(2, "GODE561231GR"), v2Bytes(2, "gODE561231GR8"),
        v2Bytes(3, "ISC001004401"), v2Bytes(3, "isc-001-0044-01"),
        v2Bytes(1, "00123456\n"), v2Bytes(2, "\xffODE561231GR8"),
        append(v2Bytes(1, "00123456"), 0),
    }
    wrongLength := v2Bytes(2, "ÑOÑE561231GR8")
    wrongLength[3] = 13 // Character count must not replace UTF-8 byte count.
    cases = append(cases, wrongLength)
    unknownVersion := v2Bytes(1, "00123456")
    unknownVersion[0] = 3
    cases = append(cases, unknownVersion)
    for i, data := range cases {
        if _, err := parseCredential(ndefCredential(data)); err == nil {
            t.Fatalf("accepted invalid case %d", i)
        }
    }
}

func TestCredentialJSONTypes(t *testing.T) {
    for _, data := range [][]byte{v2Bytes(1, "00123456"), v2Bytes(2, "ÑOÑE561231GR8"), v2Bytes(3, "ISC-001-0044-01"), sampleMessage()[3+len(credentialMIME):]} {
        c, err := decodeCredential(data)
        if err != nil {
            t.Fatal(err)
        }
        reading := cardReading{Type: c.Type, Identifier: c.Identifier, UserID: c.UserID, CredentialVersion: c.Version}
        encoded, err := json.Marshal(agentEvent{Version: 1, Type: "credential", Data: reading})
        if err != nil {
            t.Fatal(err)
        }
        var event struct {
            Version int
            Type    string
            Data    map[string]any
        }
        if err := json.Unmarshal(encoded, &event); err != nil {
            t.Fatal(err)
        }
        if event.Version != 1 || event.Type != "credential" || event.Data["type"] != c.Type || event.Data["identifier"] != c.Identifier {
            t.Fatal(string(encoded))
        }
        userID, exists := event.Data["userId"]
        if (c.Type == "student" && userID != c.Identifier) || (c.Type != "student" && exists) {
            t.Fatal(string(encoded))
        }
    }
}
