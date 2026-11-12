package main

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestCommandFraming(t *testing.T) {
    input := strings.NewReader("{\"version\":1,\"id\":\"a-1\",\"command\":\"status\"}\r\nnot-json\n{\"version\":2,\"id\":\"b\",\"command\":\"resume\"}\n{\"version\":1,\"id\":\"c\",\"command\":\"pause\"}\n")
    commands:=make(chan agentCommand,8)
    scanCommands(input,commands,make(chan struct{}))
    var received []agentCommand
    for command:=range commands { received=append(received,command) }
    if len(received)!=4 || received[0].Command!="status" || received[0].ID!="a-1" || received[3].Command!="pause" { t.Fatal("se perdieron órdenes o sus identificadores") }
    if received[1].parseError==nil || received[2].parseError==nil { t.Fatal("se aceptó una orden inválida") }
}

func TestProtocolEventIsOneJSONLine(t *testing.T) {
    event:=agentEvent{Version:1,Type:"credential",Data:&cardReading{UID:"04D317023C3E03",UserID:"00123456",SignatureValid:true,KeysSource:"caché"}}
    var output strings.Builder
    if err:=json.NewEncoder(&output).Encode(event);err!=nil{t.Fatal(err)}
    if strings.Count(output.String(),"\n")!=1 {t.Fatal("el evento no ocupa una sola línea")}
    var decoded map[string]any
    if err:=json.Unmarshal([]byte(output.String()),&decoded);err!=nil{t.Fatal(err)}
    if decoded["version"]!=float64(1) || decoded["type"]!="credential" {t.Fatal("envoltura incorrecta")}
}
