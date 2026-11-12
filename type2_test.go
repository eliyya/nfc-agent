package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

type type2Memory struct {
	memory   []byte
	pages    []byte
	failPage int
}

func (tag *type2Memory) Transmit(command []byte) ([]byte, error) {
	if len(command) != 5 || command[0] != 0xff || command[1] != 0xb0 || command[2] != 0 || command[4] != 4 {
		return nil, fmt.Errorf("se esperaba únicamente una lectura de página: %X", command)
	}
	page := int(command[3])
	tag.pages = append(tag.pages, command[3])
	if page == tag.failPage {
		return []byte{0x69, 0x82}, nil
	}
	start := page * 4
	if start+4 > len(tag.memory) {
		return nil, fmt.Errorf("lectura fuera de memoria")
	}
	response := append([]byte{}, tag.memory[start:start+4]...)
	return append(response, 0x90, 0), nil
}

func testType2Memory() *type2Memory {
	memory := make([]byte, 16+144)
	copy(memory[12:16], []byte{0xe1, 0x10, 0x12, 0})
	message := sampleMessage()
	data := append([]byte{0, 3, byte(len(message))}, message...)
	data = append(data, 0xfe)
	copy(memory[16:], data)
	return &type2Memory{memory: memory, failPage: -1}
}

func TestRecognizeBothObservedCards(t *testing.T) {
	for _, test := range []struct {
		atr  string
		kind uint16
	}{
		{"3b8f8001804f0ca000000306030001000000006a", tagClassic1K},
		{"3b8f8001804f0ca0000003060300030000000068", tagUltralight},
	} {
		atr, err := hex.DecodeString(test.atr)
		if err != nil {
			t.Fatal(err)
		}
		kind, err := tagTypeFromATR(atr)
		if err != nil || kind != test.kind {
			t.Fatalf("tipo detectado %d: %v", kind, err)
		}
	}
	for _, atr := range [][]byte{nil, {1, 2, 3}, make([]byte, 20)} {
		if _, err := tagTypeFromATR(atr); err == nil {
			t.Fatal("se aceptó un ATR desconocido")
		}
	}
}

func TestReadType2AndroidCredential(t *testing.T) {
	tag := testType2Memory()
	message, err := readType2NDEF(tag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, sampleMessage()) {
		t.Fatal("los datos NDEF cambiaron durante la lectura")
	}
	credential, err := parseCredential(message)
	if err != nil {
		t.Fatal(err)
	}
	if credential.UserID != "01234567" {
		t.Fatalf("userId inesperado: %s", credential.UserID)
	}
	if tag.pages[0] != 3 || tag.pages[len(tag.pages)-1] != 39 {
		t.Fatal("la lectura excedió o no completó el área declarada")
	}
}

func TestType2RejectsInvalidMemory(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*type2Memory)
	}{
		{"sin NDEF", func(tag *type2Memory) { tag.memory[12] = 0 }},
		{"versión", func(tag *type2Memory) { tag.memory[13] = 0x20 }},
		{"lectura protegida", func(tag *type2Memory) { tag.memory[15] = 0xf0 }},
		{"vacía", func(tag *type2Memory) { tag.memory[14] = 0 }},
		{"requiere sectores", func(tag *type2Memory) { tag.memory[14] = 0xff }},
		{"fallo de página", func(tag *type2Memory) { tag.failPage = 8 }},
		{"TLV truncado", func(tag *type2Memory) { tag.memory[17] = 255; tag.memory[18] = 1; tag.memory[19] = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			tag := testType2Memory()
			test.mutate(tag)
			if _, err := readType2NDEF(tag); err == nil {
				t.Fatal("se aceptó una memoria inválida")
			}
		})
	}
}
