package main

import (
    "bufio"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "regexp"
    "time"

    "github.com/ebfe/scard"
)

type cardReading struct {
    UID               string `json:"uid"`
    ATR               string `json:"atr"`
    Technology        string `json:"technology"`
    UserID            string `json:"userId,omitempty"`
    Type              string `json:"type"`
    Identifier        string `json:"identifier"`
    KeyID             byte   `json:"keyId"`
    CredentialVersion byte   `json:"credentialVersion"`
    SignatureValid    bool   `json:"signatureValid"`
    KeysSource        string `json:"keysSource"`
}

type agentEvent struct {
    Version int    `json:"version"`
    Type    string `json:"type"`
    ID      string `json:"id,omitempty"`
    Data    any    `json:"data,omitempty"`
    Error   string `json:"error,omitempty"`
}

type agentCommand struct {
    Version    int    `json:"version"`
    ID         string `json:"id"`
    Command    string `json:"command"`
    parseError error
}

var commandID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func scanCommands(input io.Reader, commands chan<- agentCommand, done <-chan struct{}) {
    defer close(commands)
    scanner := bufio.NewScanner(input)
    scanner.Buffer(make([]byte, 4096), 16384)
    for scanner.Scan() {
        var command agentCommand
        err := json.Unmarshal(scanner.Bytes(), &command)
        if err != nil || command.Version != 1 || !commandID.MatchString(command.ID) {
            command.ID = ""
            command.parseError = fmt.Errorf("se esperaba una orden JSON versión 1 con id válido")
        }
        select {
        case commands <- command:
        case <-done:
            return
        }
    }
    if err := scanner.Err(); err != nil {
        select {
        case commands <- agentCommand{parseError: fmt.Errorf("entrada de protocolo inválida: %w", err)}:
        case <-done:
        }
    }
}

func runStdio(input io.Reader, output io.Writer, options keySyncOptions) error {
    encoder := json.NewEncoder(output)
    emit := func(kind, id string, data any, err error) error {
        event := agentEvent{Version: 1, Type: kind, ID: id, Data: data}
        if err != nil {
            event.Error = err.Error()
        }
        return encoder.Encode(event)
    }
    ctx, err := scard.EstablishContext()
    if err != nil {
        _ = emit("error", "", nil, fmt.Errorf("iniciar PC/SC: %w", err))
        return err
    }
    defer ctx.Release()
    done := make(chan struct{})
    defer close(done)
    commands := make(chan agentCommand, 16)
    go scanCommands(input, commands, done)
    ticker := time.NewTicker(250 * time.Millisecond)
    defer ticker.Stop()
    paused := true
    reader := ""
    var states []scard.ReaderState
    var retryAt time.Time
    known, present := false, false
    status := func() map[string]any {
        return map[string]any{"paused": paused, "connected": reader != "", "reader": reader}
    }
    if err := emit("ready", "", status(), nil); err != nil {
        return err
    }
    for {
        select {
        case command, ok := <-commands:
            if !ok {
                _ = emit("stopped", "", nil, nil)
                return nil
            }
            if command.parseError != nil {
                if err := emit("error", "", nil, command.parseError); err != nil {
                    return err
                }
                continue
            }
            var response any
            var commandError error
            stop := false
            switch command.Command {
            case "status":
                response = status()
            case "pause":
                paused = true
                response = status()
            case "resume":
                paused = false
                known = false
                if len(states) > 0 {
                    states[0].CurrentState = scard.StateUnaware
                }
                response = status()
            case "refresh_keys":
                if options.Offline {
                    commandError = fmt.Errorf("no se pueden refrescar claves en modo offline")
                    break
                }
                refresh := options
                refresh.Refresh = true
                keys, source, err := syncIssuerKeys(refresh)
                commandError = err
                if err == nil {
                    response = map[string]any{"keyCount": len(keys), "source": source}
                    if err := emit("keys_status", "", response, nil); err != nil {
                        return err
                    }
                }
            case "shutdown":
                response = status()
                stop = true
            default:
                commandError = fmt.Errorf("orden desconocida: %s", command.Command)
            }
            if err := emit("response", command.ID, response, commandError); err != nil {
                return err
            }
            if stop {
                _ = emit("stopped", "", nil, nil)
                return nil
            }
        case <-ticker.C:
            if reader == "" {
                if time.Now().Before(retryAt) {
                    continue
                }
                retryAt = time.Now().Add(time.Second)
                readers, err := ctx.ListReaders()
                if errors.Is(err, scard.ErrNoReadersAvailable) || (err == nil && len(readers) == 0) {
                    continue
                }
                if err != nil {
                    if err := emit("error", "", nil, fmt.Errorf("listar lectores: %w", err)); err != nil {
                        return err
                    }
                    continue
                }
                reader = readers[0]
                states = []scard.ReaderState{{Reader: reader, CurrentState: scard.StateUnaware}}
                known = false
                if err := emit("reader_status", "", status(), nil); err != nil {
                    return err
                }
            }
            err := ctx.GetStatusChange(states, 100*time.Millisecond)
            if errors.Is(err, scard.ErrTimeout) {
                continue
            }
            if err != nil || states[0].EventState&(scard.StateUnknown|scard.StateUnavailable) != 0 {
                reader = ""
                states = nil
                known = false
                if err := emit("reader_status", "", status(), nil); err != nil {
                    return err
                }
                continue
            }
            state := states[0].EventState
            states[0].CurrentState = state &^ scard.StateChanged
            nowPresent := state&scard.StatePresent != 0
            if !nowPresent && state&scard.StateEmpty == 0 {
                continue
            }
            if known && nowPresent == present {
                continue
            }
            known, present = true, nowPresent
            if !present {
                if err := emit("card_removed", "", nil, nil); err != nil {
                    return err
                }
                continue
            }
            if err := emit("card_present", "", nil, nil); err != nil {
                return err
            }
            if paused {
                continue
            }
            reading, err := leerCredencial(ctx, reader, "", 0, options)
            if err != nil {
                if err := emit("error", "", nil, err); err != nil {
                    return err
                }
                continue
            }
            if err := emit("credential", "", reading, nil); err != nil {
                return err
            }
        }
    }
}
