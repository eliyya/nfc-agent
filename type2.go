package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	tagClassic1K  uint16 = 1
	tagUltralight uint16 = 3
)

func tagTypeFromATR(atr []byte) (uint16, error) {
	prefix := []byte{0x80, 0x4f, 0x0c, 0xa0, 0, 0, 3, 6, 3}
	if len(atr) != 20 || !bytes.Equal(atr[4:13], prefix) {
		return 0, fmt.Errorf("el ATR no identifica una tarjeta MIFARE compatible")
	}
	kind := binary.BigEndian.Uint16(atr[13:15])
	if kind != tagClassic1K && kind != tagUltralight {
		return 0, fmt.Errorf("tipo de tarjeta PC/SC %04X todavía no soportado", kind)
	}
	return kind, nil
}

// ACR122U READ BINARY uses page addresses for Ultralight/NTAG Type 2 tags.
func readType2Page(card cardTransport, page int) ([]byte, error) {
	if page < 0 || page > 255 {
		return nil, fmt.Errorf("página Type 2 fuera de rango: %d", page)
	}
	data, err := transmitOK(card, []byte{0xff, 0xb0, 0, byte(page), 4})
	if err != nil {
		return nil, fmt.Errorf("leer página Type 2 %d: %w", page, err)
	}
	if len(data) != 4 {
		return nil, fmt.Errorf("página Type 2 %d: se esperaban 4 bytes, llegaron %d", page, len(data))
	}
	return data, nil
}

func readType2NDEF(card cardTransport) ([]byte, error) {
	cc, err := readType2Page(card, 3)
	if err != nil {
		return nil, err
	}
	if cc[0] != 0xe1 {
		return nil, fmt.Errorf("la tarjeta Type 2 no tiene un Capability Container NDEF válido")
	}
	if cc[1]>>4 != 1 {
		return nil, fmt.Errorf("versión Type 2 NDEF no soportada: %02X", cc[1])
	}
	if cc[3]>>4 != 0 {
		return nil, fmt.Errorf("la tarjeta Type 2 no permite lectura NDEF pública")
	}
	size := int(cc[2]) * 8
	if size == 0 {
		return nil, fmt.Errorf("la tarjeta Type 2 declara un área NDEF vacía")
	}
	if size > 252*4 {
		return nil, fmt.Errorf("esta tarjeta Type 2 requiere selección de sectores, todavía no soportada")
	}
	data := make([]byte, 0, size)
	for page := 4; len(data) < size; page++ {
		chunk, err := readType2Page(card, page)
		if err != nil {
			return nil, err
		}
		data = append(data, chunk...)
	}
	return ndefFromTLV(data)
}
