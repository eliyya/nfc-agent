package main

import (
    "encoding/binary"
    "fmt"
    "regexp"
    "unicode/utf8"
)

const credentialMIME = "application/vnd.eli.access"

type Credential struct {
    Version    byte
    KeyID      byte
    UserID     string
    Type       string
    Identifier string
    Payload    []byte
    Signature  []byte
}

// ndefFromTLV extracts the NDEF message from the logical NFC data area.
func ndefFromTLV(data []byte) ([]byte, error) {
    for pos := 0; pos < len(data); {
        tag := data[pos]
        pos++
        if tag == 0 {
            continue
        }
        if tag == 0xfe {
            break
        }
        if pos >= len(data) {
            return nil, fmt.Errorf("TLV sin longitud")
        }
        n := int(data[pos])
        pos++
        if n == 255 {
            if len(data)-pos < 2 {
                return nil, fmt.Errorf("longitud TLV incompleta")
            }
            n = int(binary.BigEndian.Uint16(data[pos : pos+2]))
            pos += 2
        }
        if n > len(data)-pos {
            return nil, fmt.Errorf("contenido TLV incompleto")
        }
        if tag == 3 {
            if n == 0 {
                return nil, fmt.Errorf("mensaje NDEF vacío")
            }
            return data[pos : pos+n], nil
        }
        pos += n
    }
    return nil, fmt.Errorf("la tarjeta no contiene un mensaje NDEF")
}

// parseCredential supports unchunked NDEF records, including long payloads and IDs.
func parseCredential(message []byte) (*Credential, error) {
    var result *Credential
    first := true
    for pos := 0; pos < len(message); {
        if len(message)-pos < 3 {
            return nil, fmt.Errorf("cabecera NDEF incompleta")
        }
        flags := message[pos]
        typeLen := int(message[pos+1])
        pos += 2
        if (flags&0x80 != 0) != first {
            return nil, fmt.Errorf("inicio NDEF inválido")
        }
        if flags&0x20 != 0 {
            return nil, fmt.Errorf("registros NDEF fragmentados no soportados")
        }
        var payloadLen uint32
        if flags&0x10 != 0 {
            payloadLen = uint32(message[pos])
            pos++
        } else {
            if len(message)-pos < 4 {
                return nil, fmt.Errorf("longitud NDEF incompleta")
            }
            payloadLen = binary.BigEndian.Uint32(message[pos : pos+4])
            pos += 4
        }
        idLen := 0
        if flags&8 != 0 {
            if pos >= len(message) {
                return nil, fmt.Errorf("ID NDEF incompleto")
            }
            idLen = int(message[pos])
            pos++
        }
        if uint64(typeLen)+uint64(idLen)+uint64(payloadLen) > uint64(len(message)-pos) {
            return nil, fmt.Errorf("registro NDEF incompleto")
        }
        typ := string(message[pos : pos+typeLen])
        pos += typeLen + idLen
        payload := message[pos : pos+int(payloadLen)]
        pos += int(payloadLen)
        if flags&7 == 2 && typ == credentialMIME {
            if result != nil {
                return nil, fmt.Errorf("varias credenciales en la misma tarjeta")
            }
            var err error
            result, err = decodeCredential(payload)
            if err != nil {
                return nil, err
            }
        }
        if flags&0x40 != 0 {
            if pos != len(message) {
                return nil, fmt.Errorf("datos después del final NDEF")
            }
            if result == nil {
                return nil, fmt.Errorf("no existe el registro %s", credentialMIME)
            }
            return result, nil
        }
        first = false
    }
    return nil, fmt.Errorf("falta el final del mensaje NDEF")
}

// The patterns match the issuer and Android codecs. Lengths are UTF-8 bytes.
var identifierFormats = map[byte]*regexp.Regexp{
    1: regexp.MustCompile(`^[0-9]{8}$`),
    2: regexp.MustCompile(`^[A-ZÑ&]{4}[0-9]{6}[A-Z0-9]{3}$`),
    3: regexp.MustCompile(`^[A-Z0-9]{3}-[0-9]{3}-[0-9]{4}-[0-9]{2}$`),
}

func decodeCredential(data []byte) (*Credential, error) {
    if len(data) < 2 {
        return nil, fmt.Errorf("cabecera de credencial incompleta")
    }
    credential := &Credential{Version: data[0], KeyID: data[1]}
    signedLength := 6
    switch credential.Version {
    case 1:
        if len(data) != 70 {
            return nil, fmt.Errorf("la credencial v1 requiere 70 bytes; contiene %d", len(data))
        }
        id := binary.BigEndian.Uint32(data[2:6])
        if id > 99999999 {
            return nil, fmt.Errorf("userId fuera del rango de 8 dígitos")
        }
        credential.Type = "student"
        credential.Identifier = fmt.Sprintf("%08d", id)
    case 2:
        if len(data) < 4 || len(data) != 4+int(data[3])+64 {
            return nil, fmt.Errorf("longitud de credencial v2 inválida")
        }
        pattern, ok := identifierFormats[data[2]]
        if !ok {
            return nil, fmt.Errorf("tipo de credencial desconocido: %d", data[2])
        }
        signedLength = 4 + int(data[3])
        identifier := data[4:signedLength]
        if !utf8.Valid(identifier) || !pattern.Match(identifier) {
            return nil, fmt.Errorf("identificador inválido para el tipo de credencial")
        }
        credential.Type = map[byte]string{1: "student", 2: "teacher", 3: "book"}[data[2]]
        credential.Identifier = string(identifier)
    default:
        return nil, fmt.Errorf("versión de credencial no soportada: %d", credential.Version)
    }
    if credential.Type == "student" {
        credential.UserID = credential.Identifier
    }
    credential.Payload = append([]byte(nil), data[:signedLength]...)
    credential.Signature = append([]byte(nil), data[signedLength:]...)
    return credential, nil
}
