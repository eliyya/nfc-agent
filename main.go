package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ebfe/scard"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	stdioMode := flag.Bool("stdio", false, "Protocolo de eventos JSON por stdin/stdout")
	once := flag.Bool("once", false, "Leer una tarjeta y salir")
	checkKeys := flag.Bool("check-keys", false, "Verificar el manifiesto del servidor sin usar el lector")
	keysURL := flag.String("keys-url", "https://nfc.eliyya.dev/keys", "URL del manifiesto firmado de claves")
	cachePath := flag.String("keys-cache", "", "Archivo de caché (por defecto, caché del usuario)")
	offline := flag.Bool("offline", false, "Usar solamente una caché verificada y vigente")
	publicKeyFile := flag.String("issuer-public-key", "", "Archivo PEM de clave emisora de confianza para verificación local")
	issuerKeyID := flag.Int("issuer-key-id", 1, "Identificador de la clave pública local")
	flag.Parse()
	if *issuerKeyID < 0 || *issuerKeyID > 255 {
		return fmt.Errorf("issuer-key-id debe estar entre 0 y 255")
	}
	if *cachePath == "" {
		path, err := defaultKeysCachePath()
		if err != nil {
			return err
		}
		*cachePath = path
	}
	keyOptions := keySyncOptions{Endpoint: *keysURL, CachePath: *cachePath, Offline: *offline}
	if *stdioMode {
		if *once || *checkKeys || *publicKeyFile != "" {
			return fmt.Errorf("-stdio no admite -once, -check-keys ni claves emisoras locales")
		}
		return runStdio(os.Stdin, os.Stdout, keyOptions)
	}
	if *checkKeys {
		keyOptions.Refresh = !*offline
		keys, source, err := syncIssuerKeys(keyOptions)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Manifiesto verificado con la raíz integrada. Claves emisoras: %d. Origen: %s\n", len(keys), source)
		fmt.Fprintln(os.Stderr, "Archivo de caché:", *cachePath)
		return nil
	}
	ctx, err := scard.EstablishContext()
	if err != nil {
		return fmt.Errorf("no se pudo iniciar PC/SC: %w", err)
	}
	defer ctx.Release()

	readers, err := ctx.ListReaders()
	if err != nil {
		return fmt.Errorf("no se pudieron listar los lectores: %w", err)
	}

	if len(readers) == 0 {
		return fmt.Errorf("no hay lectores conectados")
	}

	// Por ahora usamos el primer lector.
	states := []scard.ReaderState{
		{
			Reader:       readers[0],
			CurrentState: scard.StateUnaware,
		},
	}

	fmt.Fprintln(os.Stderr, "Escuchando:", readers[0])
	fmt.Fprintln(os.Stderr, "Acerca una tarjeta. Ctrl+C para salir.")

	var estadoConocido bool
	var tarjetaPresente bool

	for {
		err := ctx.GetStatusChange(states, -1)
		if err != nil {
			return fmt.Errorf("error al esperar una tarjeta: %w", err)
		}

		state := states[0].EventState

		// Reconocer el estado recibido y limpiar la bandera de cambio.
		states[0].CurrentState = state &^ scard.StateChanged

		presente := state&scard.StatePresent != 0
		vacio := state&scard.StateEmpty != 0

		if !presente && !vacio {
			continue
		}

		// Ignorar avisos que no cambian la presencia.
		if estadoConocido && presente == tarjetaPresente {
			continue
		}

		estadoConocido = true
		tarjetaPresente = presente

		if presente {
			reading, err := leerCredencial(ctx, readers[0], *publicKeyFile, byte(*issuerKeyID), keyOptions)
			if err != nil {
				if *once {
					return err
				}
				fmt.Fprintln(os.Stderr, "Credencial no validada:", err)
				continue
			}

			fmt.Fprintln(os.Stderr, "UID:", reading.UID)
			if *once {
				return nil
			}
		} else {
			fmt.Fprintln(os.Stderr, "Lector sin tarjeta")
		}
	}
}

func leerCredencial(ctx *scard.Context, reader, publicKeyFile string, issuerKeyID byte, options keySyncOptions) (*cardReading, error) {
	card, err := ctx.Connect(
		reader,
		scard.ShareShared,
		scard.ProtocolAny,
	)
	if err != nil {
		return nil, fmt.Errorf("conectar con la tarjeta: %w", err)
	}
	defer card.Disconnect(scard.LeaveCard)

	status, err := card.Status()
	if err != nil {
		return nil, fmt.Errorf("consultar información de la tarjeta: %w", err)
	}
	fmt.Fprintf(os.Stderr, "ATR: % X\n", status.Atr)

	// Comando del ACR122U para obtener el UID.
	command := []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}

	response, err := card.Transmit(command)
	if err != nil {
		return nil, fmt.Errorf("leer UID: %w", err)
	}

	if len(response) < 2 {
		return nil, fmt.Errorf("respuesta incompleta: % X", response)
	}

	// Los últimos dos bytes indican el resultado del comando.
	dataEnd := len(response) - 2
	sw1 := response[dataEnd]
	sw2 := response[dataEnd+1]

	if sw1 != 0x90 || sw2 != 0x00 {
		return nil, fmt.Errorf("lectura rechazada: %02X %02X", sw1, sw2)
	}

	uid := response[:dataEnd]
	if len(uid) == 0 {
		return nil, fmt.Errorf("el lector devolvió un UID vacío")
	}
	fmt.Fprintf(os.Stderr, "UID detectado: %X\n", uid)
	kind, err := tagTypeFromATR(status.Atr)
	if err != nil {
		return nil, err
	}
	technology := ""
	var message []byte
	switch kind {
	case tagClassic1K:
		technology = "classic1k"
		fmt.Fprintln(os.Stderr, "Tipo: MIFARE Classic 1K")
		message, err = readClassicNDEF(card)
	case tagUltralight:
		technology = "type2"
		fmt.Fprintln(os.Stderr, "Tipo: MIFARE Ultralight / NTAG (NFC Type 2)")
		message, err = readType2NDEF(card)
	}
	if err != nil {
		return nil, err
	}
	credential, err := parseCredential(message)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Credencial leída: versión=%d keyId=%d userId=%s\n", credential.Version, credential.KeyID, credential.UserID)
	var keys map[byte]issuerKey
	keySource := "local"
	if publicKeyFile != "" {
		keys, err = localIssuerKey(publicKeyFile, issuerKeyID)
		fmt.Fprintln(os.Stderr, "Verificación local: estado de revocación no consultado")
	} else {
		var source string
		keys, source, err = syncIssuerKeys(options)
		keySource = source
		if err == nil {
			fmt.Fprintln(os.Stderr, "Claves verificadas desde:", source)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("tarjeta leída, pero no se pudieron obtener claves de confianza: %w", err)
	}
	if err := verifyCredential(credential, keys); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "Firma Ed25519 VÁLIDA. Usuario verificado: %s\n", credential.UserID)

	return &cardReading{UID: fmt.Sprintf("%X", uid), ATR: fmt.Sprintf("%X", status.Atr), Technology: technology, UserID: credential.UserID, KeyID: credential.KeyID, CredentialVersion: credential.Version, SignatureValid: true, KeysSource: keySource}, nil
}
