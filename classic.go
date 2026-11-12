package main

import (
	"fmt"
	"github.com/ebfe/scard"
)

type cardTransport interface {
	Transmit([]byte) ([]byte, error)
}

func transmitOK(card cardTransport, command []byte) ([]byte, error) {
	response, err := card.Transmit(command)
	if err != nil {
		return nil, err
	}
	if len(response) < 2 {
		return nil, fmt.Errorf("respuesta PC/SC incompleta")
	}
	n := len(response) - 2
	if response[n] != 0x90 || response[n+1] != 0 {
		return nil, fmt.Errorf("comando %02X: estado %02X%02X", command[1], response[n], response[n+1])
	}
	return response[:n], nil
}

func authenticate(card *scard.Card, block byte, key []byte) error {
	command := append([]byte{0xff, 0x82, 0, 0, 6}, key...)
	if _, err := transmitOK(card, command); err != nil {
		return err
	}
	_, err := transmitOK(card, []byte{0xff, 0x86, 0, 0, 5, 1, 0, block, 0x60, 0})
	return err
}

func readBlock(card *scard.Card, block byte) ([]byte, error) {
	data, err := transmitOK(card, []byte{0xff, 0xb0, 0, block, 16})
	if err != nil {
		return nil, fmt.Errorf("bloque %d: %w", block, err)
	}
	if len(data) != 16 {
		return nil, fmt.Errorf("bloque %d: longitud inesperada %d", block, len(data))
	}
	return data, nil
}

// Only reads sectors explicitly assigned to NDEF in MAD1. Never writes the card.
func readClassicNDEF(card *scard.Card) ([]byte, error) {
	if err := authenticate(card, 1, []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}); err != nil {
		return nil, fmt.Errorf("no se puede leer el directorio NDEF (MAD); confirma que la tarjeta fue grabada/formateada en Android: %w", err)
	}
	b1, err := readBlock(card, 1)
	if err != nil {
		return nil, err
	}
	b2, err := readBlock(card, 2)
	if err != nil {
		return nil, err
	}
	mad := append(b1, b2...)
	var data []byte
	for sector := 1; sector <= 15; sector++ {
		// NFC application identifier as stored in the MAD: 03 E1.
		if mad[sector*2] != 0x03 || mad[sector*2+1] != 0xe1 {
			continue
		}
		block := byte(sector * 4)
		if err := authenticate(card, block, []byte{0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}); err != nil {
			return nil, fmt.Errorf("autenticar sector NDEF %d: %w", sector, err)
		}
		for offset := byte(0); offset < 3; offset++ {
			chunk, err := readBlock(card, block+offset)
			if err != nil {
				return nil, err
			}
			data = append(data, chunk...)
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("el directorio no contiene sectores NDEF")
	}
	return ndefFromTLV(data)
}
